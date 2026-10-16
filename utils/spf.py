import ipaddress
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

import dns.exception
import dns.resolver
from flask import flash, jsonify, make_response, redirect, render_template, request, url_for

from utils.dns import resolves_to_non_public_ip, valid_dns_target
from utils.task_access import delete_owned_task, is_private_task, module_history, visible_task


QUALIFIER_RESULTS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MECHANISMS = {"all", "include", "a", "mx", "ip4", "ip6", "exists", "ptr"}
MODIFIERS = {"redirect", "exp"}


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def valid_spf_domain(value):
    return bool(value and not _is_ip_address(value) and valid_dns_target(value) and "." in value)


def _txt_records(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6
    try:
        answers = resolver.resolve(domain, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as exc:
        return [], f"TXT lookup failed: {exc}"
    records = []
    for answer in answers:
        chunks = getattr(answer, "strings", None)
        if chunks:
            records.append("".join(chunk.decode("utf-8", "replace") for chunk in chunks))
        else:
            records.append(answer.to_text().replace('"', ""))
    return records, None


def _deprecated_spf_records(domain):
                                                                   
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6
    try:
        answers = resolver.resolve(domain, "SPF", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as exc:
        return [], f"Deprecated SPF RR lookup failed: {exc}"
    records = []
    for answer in answers:
        chunks = getattr(answer, "strings", None)
        records.append("".join(chunk.decode("utf-8", "replace") for chunk in chunks) if chunks else answer.to_text().replace('"', ""))
    return records, None


def _split_term(term):
    qualifier = "+"
    if term[:1] in QUALIFIER_RESULTS:
        qualifier, term = term[0], term[1:]
    if "=" in term:
        name, value = term.split("=", 1)
        return {"term": term, "kind": "modifier", "name": name.lower(), "value": value, "qualifier": qualifier, "cidr": None}
    name, separator, remainder = term.partition(":")
    if not separator:
        name, separator, remainder = term.partition("/")
        remainder = f"/{remainder}" if separator else ""
    value, cidr = remainder, None
    if "/" in remainder:
        value, cidr = remainder.split("/", 1)
    elif separator == "/":
        value, cidr = "", remainder.lstrip("/")
    return {"term": term, "kind": "mechanism", "name": name.lower(), "value": value or None, "qualifier": qualifier, "cidr": cidr or None}


def _parse_record(record):
    terms = record.split()
    return [_split_term(term) for term in terms[1:]]


def _validation_report(domain, records):
    spf_candidates = [record for record in records if record.lower().startswith("v=spf1")]
    spf_records = [record for record in spf_candidates if len(record) == 6 or record[6].isspace()]
    errors, warnings, mechanisms = [], [], []
    if not spf_records:
        if spf_candidates:
            return spf_candidates[0], mechanisms, ["Invalid SPF version syntax: 'v=spf1' must be followed by whitespace before the first mechanism."], warnings, 0
        return None, mechanisms, ["No SPF record was found for this domain."], warnings, 0
    if len(spf_records) > 1:
        errors.append("Multiple SPF records were found. SPF permits only one record.")
    record = spf_records[0]
    terms = _parse_record(record)
    lookup_estimate = 0
    seen_all = False
    seen_redirect = False
    for item in terms:
        name = item["name"]
        if item["kind"] == "modifier":
            if item["qualifier"] != "+":
                errors.append(f"Modifier '{item['term']}' cannot use a qualifier.")
            if name not in MODIFIERS:
                errors.append(f"Unknown SPF modifier '{name}'.")
            if not item["value"]:
                errors.append(f"Modifier '{name}' requires a value.")
            if name == "redirect":
                lookup_estimate += 1
                if seen_redirect:
                    errors.append("The redirect modifier appears more than once.")
                seen_redirect = True
            continue

        mechanisms.append(item)
        if name not in MECHANISMS:
            errors.append(f"Unknown SPF mechanism '{name}'.")
            continue
        if seen_all:
            warnings.append(f"'{item['term']}' is unreachable because it appears after all.")
        if name == "all":
            seen_all = True
            if item["value"] or item["cidr"]:
                errors.append(f"'{item['term']}' is not valid: all cannot have a value or CIDR length.")
        if name in {"include", "a", "mx", "exists", "ptr"}:
            lookup_estimate += 1
        if name in {"ip4", "ip6"}:
            if not item["value"]:
                errors.append(f"'{name}' requires an IP address.")
                continue
            try:
                default_prefix = 32 if name == "ip4" else 128
                prefix = item["cidr"] or str(default_prefix)
                network = ipaddress.ip_network(f"{item['value']}/{prefix}", strict=False)
                if (name == "ip4" and network.version != 4) or (name == "ip6" and network.version != 6):
                    errors.append(f"'{item['term']}' uses the wrong address family.")
            except ValueError:
                errors.append(f"'{item['term']}' has an invalid IP network.")
        elif name in {"include", "exists"} and not item["value"]:
            errors.append(f"'{name}' requires a domain specification.")
        elif name in {"include", "a", "mx", "exists"} and item["value"] and any(marker in item["value"] for marker in ("+all", "-all", "~all", "?all")):
            errors.append(f"'{item['term']}' appears to combine SPF terms without whitespace.")
        elif name == "ptr":
            warnings.append("The ptr mechanism is discouraged and may not be supported by receivers.")
        if item["cidr"] and name not in {"ip4", "ip6", "a", "mx"}:
            errors.append(f"'{item['term']}' cannot use a CIDR length.")
    if lookup_estimate > 10:
        errors.append(f"The SPF policy can require {lookup_estimate} DNS lookups; SPF permits at most 10.")
    return record, mechanisms, errors, warnings, lookup_estimate


def _mx_hosts(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6
    try:
        answers = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        return [answer.exchange.to_text().rstrip(".") for answer in answers], None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as exc:
        return [], str(exc)


def _audit_spf_dependencies(domain, record, depth=0, path=None, seen_includes=None, audit=None):
                                                                                         
    if audit is None:
        audit = {"included_lookups": [], "void_lookups": [], "recursive_loops": [], "duplicate_includes": [], "ptr_used": False}
    path = path or []
    seen_includes = seen_includes if seen_includes is not None else set()
    if depth >= 10:
        audit["recursive_loops"].append("SPF dependency depth exceeded 10 lookups.")
        return audit

    redirect_target = None
    for item in _parse_record(record):
        name, value = item["name"], item["value"]
        if item["kind"] == "modifier":
            if name == "redirect" and value:
                redirect_target = value
            continue
        if name == "ptr":
            audit["ptr_used"] = True
            continue
        if name == "include" and value:
            if value in seen_includes:
                audit["duplicate_includes"].append(value)
            seen_includes.add(value)
            if value in path or value == domain:
                audit["recursive_loops"].append("  ".join(path + [domain, value]))
                continue
            records, lookup_error = _txt_records(value)
            child_record, _terms, child_errors, _warnings, _estimate = _validation_report(value, records)
            if lookup_error:
                audit["included_lookups"].append({"domain": value, "status": "Unknown", "detail": lookup_error})
            elif not child_record:
                audit["included_lookups"].append({"domain": value, "status": "Error", "detail": "No SPF record published."})
                audit["void_lookups"].append({"mechanism": "include", "target": value})
            elif child_errors:
                audit["included_lookups"].append({"domain": value, "status": "Error", "detail": "; ".join(child_errors)})
            else:
                audit["included_lookups"].append({"domain": value, "status": "Pass", "detail": "SPF record found."})
                _audit_spf_dependencies(value, child_record, depth + 1, path + [domain], seen_includes, audit)
        elif name == "a":
            target = value or domain
            addresses, lookup_error = _addresses_for(target)
            if not lookup_error and not addresses:
                audit["void_lookups"].append({"mechanism": "a", "target": target})
        elif name == "mx":
            target = value or domain
            hosts, lookup_error = _mx_hosts(target)
            if not lookup_error and not hosts:
                audit["void_lookups"].append({"mechanism": "mx", "target": target})
        elif name == "exists" and value and "%{" not in value:
            addresses, lookup_error = _addresses_for(value)
            if not lookup_error and not addresses:
                audit["void_lookups"].append({"mechanism": "exists", "target": value})

    if redirect_target:
        if redirect_target in path or redirect_target == domain:
            audit["recursive_loops"].append("  ".join(path + [domain, redirect_target]))
            return audit
        records, lookup_error = _txt_records(redirect_target)
        child_record, _terms, child_errors, _warnings, _estimate = _validation_report(redirect_target, records)
        if lookup_error:
            audit["included_lookups"].append({"domain": redirect_target, "status": "Unknown", "detail": lookup_error})
        elif not child_record:
            audit["included_lookups"].append({"domain": redirect_target, "status": "Error", "detail": "No SPF record published for redirect."})
            audit["void_lookups"].append({"mechanism": "redirect", "target": redirect_target})
        elif child_errors:
            audit["included_lookups"].append({"domain": redirect_target, "status": "Error", "detail": "; ".join(child_errors)})
        else:
            audit["included_lookups"].append({"domain": redirect_target, "status": "Pass", "detail": "Redirect SPF record found."})
            _audit_spf_dependencies(redirect_target, child_record, depth + 1, path + [domain], seen_includes, audit)
    return audit


def _policy_checks(record, txt_records, errors, warnings, dependency_audit, deprecated_records, deprecated_error):
    terms = _parse_record(record) if record else []
    all_position = next((index for index, item in enumerate(terms) if item["kind"] == "mechanism" and item["name"] == "all"), None)
    trailing_terms = terms[all_position + 1:] if all_position is not None else []
    syntax_errors = [error for error in errors if "Multiple SPF" not in error and "No SPF record" not in error]
    duplicate_includes = sorted(set(dependency_audit["duplicate_includes"]))
    checks = [
        {"name": "Record published", "status": "Pass" if record else "Error", "detail": "One SPF TXT record is published." if record else "No SPF TXT record is published."},
        {"name": "Deprecated SPF RR", "status": "Warning" if deprecated_records else ("Unknown" if deprecated_error else "Pass"), "detail": "Deprecated SPF DNS resource record is published; use TXT only." if deprecated_records else (deprecated_error or "No deprecated SPF DNS resource record found.")},
        {"name": "Multiple records", "status": "Error" if len([item for item in txt_records if item.lower().startswith('v=spf1')]) > 1 else "Pass", "detail": "More than one SPF TXT record was found." if len([item for item in txt_records if item.lower().startswith('v=spf1')]) > 1 else "Only one SPF TXT record was found."},
        {"name": "Characters after all", "status": "Warning" if trailing_terms else "Pass", "detail": "Unreachable directives after all: " + ", ".join(item["term"] for item in trailing_terms) if trailing_terms else "No directives appear after all."},
        {"name": "Syntax check", "status": "Error" if syntax_errors else "Pass", "detail": "; ".join(syntax_errors) if syntax_errors else "SPF mechanisms and modifiers parsed successfully."},
        {"name": "Included lookups", "status": "Error" if any(item["status"] == "Error" for item in dependency_audit["included_lookups"]) else ("Unknown" if any(item["status"] == "Unknown" for item in dependency_audit["included_lookups"]) else "Pass"), "detail": f"{len(dependency_audit['included_lookups'])} include/redirect lookup(s) inspected."},
        {"name": "Recursive loop", "status": "Error" if dependency_audit["recursive_loops"] else "Pass", "detail": "; ".join(dependency_audit["recursive_loops"]) if dependency_audit["recursive_loops"] else "No include or redirect loop detected."},
        {"name": "Duplicate include", "status": "Warning" if duplicate_includes else "Pass", "detail": "Repeated include target(s): " + ", ".join(duplicate_includes) if duplicate_includes else "No repeated include targets detected."},
        {"name": "PTR check", "status": "Warning" if dependency_audit["ptr_used"] else "Pass", "detail": "The deprecated/discouraged ptr mechanism is present." if dependency_audit["ptr_used"] else "The ptr mechanism is not used."},
        {"name": "Void lookup", "status": "Error" if len(dependency_audit["void_lookups"]) > 2 else ("Warning" if dependency_audit["void_lookups"] else "Pass"), "detail": f"{len(dependency_audit['void_lookups'])} void lookup(s) detected."},
    ]
    return checks, trailing_terms


def _addresses_for(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6
    addresses = []
    try:
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
                addresses.extend(ipaddress.ip_address(answer.to_text()) for answer in answers)
            except dns.resolver.NXDOMAIN:
                return [], None
            except dns.resolver.NoAnswer:
                continue
        return addresses, None
    except dns.exception.DNSException as exc:
        return [], str(exc)


def _matches_network(sender_ip, addresses, cidr, family):
    prefix = int(cidr) if cidr else (32 if family == 4 else 128)
    try:
        return any(sender_ip.version == address.version and sender_ip in ipaddress.ip_network(f"{address}/{prefix}", strict=False) for address in addresses)
    except ValueError:
        return False


def _expand_exists(value, domain, sender_ip):
    expanded = value.replace("%{i}", str(sender_ip)).replace("%{d}", domain)
    return None if "%{" in expanded else expanded


def _evaluate_sender(domain, sender_ip, depth=0, visited=None, trace=None):
    visited, trace = visited or set(), trace if trace is not None else []
    if depth >= 10 or domain in visited:
        return {"result": "permerror", "reason": "SPF include/redirect recursion limit reached.", "trace": trace}
    visited.add(domain)
    records, lookup_error = _txt_records(domain)
    if lookup_error:
        return {"result": "temperror", "reason": lookup_error, "trace": trace}
    record, terms, errors, _warnings, _estimate = _validation_report(domain, records)
    if errors or not record:
        return {"result": "permerror", "reason": "; ".join(errors), "trace": trace}

    redirect_target = None
    for item in _parse_record(record):
        name, value = item["name"], item["value"]
        if item["kind"] == "modifier":
            if name == "redirect":
                redirect_target = value
            continue
        if name == "all":
            result = QUALIFIER_RESULTS[item["qualifier"]]
            trace.append(f"{domain}: {item['term']} matched  {result}")
            return {"result": result, "reason": "Matched all mechanism.", "trace": trace}
        if name in {"ip4", "ip6"}:
            try:
                prefix = item["cidr"] or ("32" if name == "ip4" else "128")
                network = ipaddress.ip_network(f"{value}/{prefix}", strict=False)
            except ValueError:
                return {"result": "permerror", "reason": f"Invalid network in {item['term']}.", "trace": trace}
            if sender_ip in network:
                result = QUALIFIER_RESULTS[item["qualifier"]]
                trace.append(f"{domain}: {item['term']} matched  {result}")
                return {"result": result, "reason": f"Matched {name} mechanism.", "trace": trace}
        elif name == "a":
            addresses, error = _addresses_for(value or domain)
            if error:
                return {"result": "temperror", "reason": f"A lookup failed: {error}", "trace": trace}
            if _matches_network(sender_ip, addresses, item["cidr"], sender_ip.version):
                result = QUALIFIER_RESULTS[item["qualifier"]]
                trace.append(f"{domain}: {item['term']} matched  {result}")
                return {"result": result, "reason": "Matched a mechanism.", "trace": trace}
        elif name == "mx":
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 6
            try:
                mx_answers = resolver.resolve(value or domain, "MX", raise_on_no_answer=False)
                hosts = [answer.exchange.to_text().rstrip(".") for answer in mx_answers]
            except dns.exception.DNSException as exc:
                return {"result": "temperror", "reason": f"MX lookup failed: {exc}", "trace": trace}
            for host in hosts:
                addresses, error = _addresses_for(host)
                if error:
                    return {"result": "temperror", "reason": f"MX host lookup failed: {error}", "trace": trace}
                if _matches_network(sender_ip, addresses, item["cidr"], sender_ip.version):
                    result = QUALIFIER_RESULTS[item["qualifier"]]
                    trace.append(f"{domain}: {item['term']} matched  {result}")
                    return {"result": result, "reason": "Matched mx mechanism.", "trace": trace}
        elif name == "include":
            included = _evaluate_sender(value, sender_ip, depth + 1, visited, trace)
            trace.append(f"{domain}: include:{value} returned {included['result']}")
            if included["result"] == "pass":
                result = QUALIFIER_RESULTS[item["qualifier"]]
                return {"result": result, "reason": f"Included policy for {value} passed.", "trace": trace}
            if included["result"] in {"temperror", "permerror"}:
                return included
        elif name == "exists":
            expanded = _expand_exists(value or "", domain, sender_ip)
            if not expanded:
                return {"result": "temperror", "reason": "The exists mechanism uses unsupported SPF macro expansion.", "trace": trace}
            addresses, error = _addresses_for(expanded)
            if error:
                return {"result": "temperror", "reason": f"Exists lookup failed: {error}", "trace": trace}
            if addresses:
                result = QUALIFIER_RESULTS[item["qualifier"]]
                trace.append(f"{domain}: {item['term']} matched  {result}")
                return {"result": result, "reason": "Matched exists mechanism.", "trace": trace}
        elif name == "ptr":
            return {"result": "temperror", "reason": "The ptr mechanism is not evaluated by Cyberseek.", "trace": trace}
    if redirect_target:
        trace.append(f"{domain}: redirect={redirect_target}")
        return _evaluate_sender(redirect_target, sender_ip, depth + 1, visited, trace)
    return {"result": "neutral", "reason": "No SPF mechanism matched the sender IP.", "trace": trace}


def check_spf(domain, sender_ip=None):
    records, lookup_error = _txt_records(domain)
    if lookup_error:
        return {"domain": domain, "record": None, "txt_records": [], "mechanisms": [], "errors": [lookup_error], "warnings": [], "lookup_estimate": 0, "authorization": None, "policy_checks": [], "dependency_audit": {"included_lookups": [], "void_lookups": [], "recursive_loops": [], "duplicate_includes": [], "ptr_used": False}}
    record, mechanisms, errors, warnings, lookup_estimate = _validation_report(domain, records)
    deprecated_records, deprecated_error = _deprecated_spf_records(domain)
    dependency_audit = _audit_spf_dependencies(domain, record) if record else {"included_lookups": [], "void_lookups": [], "recursive_loops": [], "duplicate_includes": [], "ptr_used": False}
    policy_checks, _trailing_terms = _policy_checks(record, records, errors, warnings, dependency_audit, deprecated_records, deprecated_error)
    authorization = None
    if sender_ip and record and not errors:
        authorization = _evaluate_sender(domain, ipaddress.ip_address(sender_ip))
        authorization["ip"] = sender_ip
        authorization["allowed"] = authorization["result"] == "pass"
    return {"domain": domain, "record": record, "txt_records": records, "mechanisms": mechanisms, "errors": errors, "warnings": warnings, "lookup_estimate": lookup_estimate, "authorization": authorization, "policy_checks": policy_checks, "dependency_audit": dependency_audit, "deprecated_spf_records": deprecated_records}


def run_spf_task(database, task_id, domain, sender_ip):
    try:
        result = json.dumps(check_spf(domain, sender_ip))
        status, error = "Complete", None
    except (dns.exception.DNSException, ValueError, OSError) as exc:
        status, result, error = "Failed", None, str(exc)[:1000]
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE spf_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?", (status, result, error, datetime.now(timezone.utc).isoformat(), task_id))


def register_spf_routes(app, database, db, current_user, login_required):
    @app.route("/recon/spf", methods=["GET", "POST"])
    @login_required
    def spf_check():
        if request.method == "POST":
            domain = request.form.get("domain", "").strip().lower().rstrip(".")
            sender_ip = request.form.get("sender_ip", "").strip()
            if not valid_spf_domain(domain):
                flash("Enter a valid domain name.", "error")
            elif resolves_to_non_public_ip(domain):
                flash("Private, local, reserved, and non-public DNS targets are not allowed.", "error")
            elif sender_ip and (not _is_ip_address(sender_ip) or not ipaddress.ip_address(sender_ip).is_global):
                flash("Enter a valid public sender IP address.", "error")
            else:
                task_id = str(uuid.uuid4())
                db().execute(
                    """INSERT INTO spf_tasks
                    (id, user_id, domain, sender_ip, status, result, error, created_at, completed_at, is_private)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (task_id, current_user()["id"], domain, sender_ip or None, "Running", None, None, datetime.now(timezone.utc).isoformat(), None, is_private_task(request.form)),
                )
                db().commit()
                threading.Thread(target=run_spf_task, args=(database, task_id, domain, sender_ip or None), daemon=True).start()
                flash("SPF task started. It will continue while you navigate the application.", "success")
                return redirect(url_for("spf_check"))
        return render_template("spf.html", history=module_history(db(), "spf", current_user()["id"], request.args), requested_domain=request.args.get("domain", "").strip().lower().rstrip("."), requested_sender_ip=request.args.get("sender_ip", "").strip())

    @app.route("/recon/spf/<task_id>")
    @login_required
    def view_spf_task(task_id):
        task = visible_task(db(), "spf_tasks", task_id, current_user()["id"])
        if not task:
            flash("SPF task not found.", "error")
            return redirect(url_for("spf_check"))
        report = json.loads(task["result"]) if task["result"] else {"errors": [], "warnings": [], "mechanisms": [], "authorization": None}
        return render_template("spf_task.html", task=task, report=report)

    @app.post("/recon/spf/<task_id>/delete")
    @login_required
    def delete_spf_task(task_id):
        delete_owned_task(db(), "spf_tasks", task_id, current_user()["id"])
        db().commit()
        flash("SPF task deleted.", "success")
        return redirect(url_for("spf_check"))

    @app.get("/recon/spf/<task_id>/export/<export_format>")
    @login_required
    def export_spf_task(task_id, export_format):
        task = visible_task(db(), "spf_tasks", task_id, current_user()["id"])
        if not task:
            flash("SPF task not found.", "error")
            return redirect(url_for("spf_check"))
        report = json.loads(task["result"]) if task["result"] else {"errors": [], "warnings": [], "mechanisms": [], "policy_checks": [], "dependency_audit": {"included_lookups": [], "void_lookups": []}}
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if export_format == "json":
            export_data = dict(task)
            export_data.pop("result", None)
            export_data["report"] = report
            response = make_response(jsonify(export_data))
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-spf-{timestamp}.json"
            return response
        if export_format == "html":
            response = make_response(render_template("spf_export.html", task=task, report=report, generated_at=datetime.now(timezone.utc)))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-spf-{timestamp}.html"
            return response
        flash("Unsupported export format.", "error")
        return redirect(url_for("view_spf_task", task_id=task_id))
