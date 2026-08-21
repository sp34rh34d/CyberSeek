import ipaddress
import json
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.exception
import dns.resolver
from flask import flash, jsonify, make_response, redirect, render_template, request, url_for

from utils.dns import resolves_to_non_public_ip, valid_dns_target
from utils.local_heuristics import ingest_local_intelligence
from utils.task_access import delete_owned_task, is_private_task, visible_task, visible_tasks


DNSBL_PROVIDERS = (
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "kind": "ip", "delist_url": "https://check.spamhaus.org/"},
    {"name": "Spamhaus SBL", "zone": "sbl.spamhaus.org", "kind": "ip", "delist_url": "https://check.spamhaus.org/"},
    {"name": "Spamhaus XBL", "zone": "xbl.spamhaus.org", "kind": "ip", "delist_url": "https://check.spamhaus.org/"},
    {"name": "Spamhaus PBL", "zone": "pbl.spamhaus.org", "kind": "ip", "delist_url": "https://check.spamhaus.org/"},
    {"name": "Barracuda Reputation", "zone": "b.barracudacentral.org", "kind": "ip", "delist_url": "https://www.barracudacentral.org/rbl/removal-request"},
    {"name": "SpamCop Blocking List", "zone": "bl.spamcop.net", "kind": "ip", "delist_url": "https://www.spamcop.net/bl.shtml"},
    {"name": "SORBS Aggregate", "zone": "dnsbl.sorbs.net", "kind": "ip", "delist_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "UCEPROTECT Level 1", "zone": "dnsbl-1.uceprotect.net", "kind": "ip", "delist_url": "https://www.uceprotect.net/en/rblcheck.php"},
    {"name": "UCEPROTECT Level 2", "zone": "dnsbl-2.uceprotect.net", "kind": "ip", "delist_url": "https://www.uceprotect.net/en/rblcheck.php"},
    {"name": "UCEPROTECT Level 3", "zone": "dnsbl-3.uceprotect.net", "kind": "ip", "delist_url": "https://www.uceprotect.net/en/rblcheck.php"},
    {"name": "SpamRATS All", "zone": "all.spamrats.com", "kind": "ip", "delist_url": "https://www.spamrats.com/removal.php"},
    {"name": "SpamRATS Auth", "zone": "auth.spamrats.com", "kind": "ip", "delist_url": "https://www.spamrats.com/removal.php"},
    {"name": "SpamRATS Dynamic", "zone": "dyna.spamrats.com", "kind": "ip", "delist_url": "https://www.spamrats.com/removal.php"},
    {"name": "SpamRATS NoPTR", "zone": "noptr.spamrats.com", "kind": "ip", "delist_url": "https://www.spamrats.com/removal.php"},
    {"name": "SpamRATS Spam", "zone": "spam.spamrats.com", "kind": "ip", "delist_url": "https://www.spamrats.com/removal.php"},
    {"name": "DroneBL", "zone": "dnsbl.dronebl.org", "kind": "ip", "delist_url": "https://dronebl.org/lookup"},
    {"name": "Blocklist.de", "zone": "bl.blocklist.de", "kind": "ip", "delist_url": "https://www.blocklist.de/en/removalrequest.html"},
    {"name": "PSBL", "zone": "psbl.surriel.com", "kind": "ip", "delist_url": "https://psbl.org/remove"},
    {"name": "JustSpam", "zone": "dnsbl.justspam.org", "kind": "ip", "delist_url": "https://justspam.org/check/"},
    {"name": "Manitu", "zone": "ix.dnsbl.manitu.net", "kind": "ip", "delist_url": "https://www.dnsbl.manitu.net/lookup.php"},
    {"name": "Spamhaus DBL", "zone": "dbl.spamhaus.org", "kind": "domain", "delist_url": "https://check.spamhaus.org/"},
    {"name": "SURBL Multi", "zone": "multi.surbl.org", "kind": "domain", "delist_url": "https://www.surbl.org/surbl-analysis"},
    {"name": "URIBL Multi", "zone": "multi.uribl.com", "kind": "domain", "delist_url": "https://uribl.com/lookup.shtml"},
    {"name": "URIBL Black", "zone": "black.uribl.com", "kind": "domain", "delist_url": "https://uribl.com/lookup.shtml"},
    {"name": "URIBL Grey", "zone": "grey.uribl.com", "kind": "domain", "delist_url": "https://uribl.com/lookup.shtml"},
    {"name": "URIBL Red", "zone": "red.uribl.com", "kind": "domain", "delist_url": "https://uribl.com/lookup.shtml"},
    {"name": "SpamEatingMonkey URI", "zone": "uribl.spameatingmonkey.net", "kind": "domain", "delist_url": "https://spameatingmonkey.com/lookup"},
    {"name": "SpamEatingMonkey Fresh", "zone": "fresh.spameatingmonkey.net", "kind": "domain", "delist_url": "https://spameatingmonkey.com/lookup"},
    {"name": "SpamEatingMonkey Fresh10", "zone": "fresh10.spameatingmonkey.net", "kind": "domain", "delist_url": "https://spameatingmonkey.com/lookup"},
    {"name": "SpamEatingMonkey Fresh15", "zone": "fresh15.spameatingmonkey.net", "kind": "domain", "delist_url": "https://spameatingmonkey.com/lookup"},
    {"name": "SpamEatingMonkey URI Red", "zone": "urired.spameatingmonkey.net", "kind": "domain", "delist_url": "https://spameatingmonkey.com/lookup"},
)


def resolve_public_ips(target):
    try:
        address = ipaddress.ip_address(target)
        return [str(address)] if address.is_global else []
    except ValueError:
        pass
    addresses = []
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(target, record_type, lifetime=5)
            addresses.extend(record.to_text() for record in answers if ipaddress.ip_address(record.to_text()).is_global)
        except dns.exception.DNSException:
            continue
    return list(dict.fromkeys(addresses))


def check_blacklists(target):
    public_ips = resolve_public_ips(target)
    is_ip_target = _is_ip_address(target)
    jobs = []
    for index, provider in enumerate(DNSBL_PROVIDERS):
        subjects = public_ips if provider["kind"] == "ip" else ([] if is_ip_target else [target])
        jobs.extend((index, provider, subject) for subject in subjects)

    rows = []
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(jobs)))) as executor:
        futures = {executor.submit(_check_provider, provider, subject): (index, subject) for index, provider, subject in jobs}
        for future in as_completed(futures):
            index, subject = futures[future]
            try:
                rows.append((index, subject, future.result()))
            except (dns.exception.DNSException, ValueError, OSError) as exc:
                rows.append((index, subject, {"provider": "Unresolved provider", "subject": subject, "kind": "unknown", "status": "Unknown", "answers": str(exc), "delist_url": None}))
    status_order = {"Listed": 0, "Unknown": 1, "Clean": 2}
    rows.sort(key=lambda row: (status_order.get(row[2]["status"], 3), row[0], row[1]))
    return {"target": target, "resolved_ips": public_ips, "checks": [row[2] for row in rows], "catalog_size": len(DNSBL_PROVIDERS)}


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _check_provider(provider, subject):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    query = _dnsbl_query(subject, provider)
    try:
        answers = [record.to_text() for record in resolver.resolve(query, "A")]
        response = ", ".join(answers)
        access_limited = any(answer.startswith("127.255.255.25") for answer in answers)
        status = "Unknown" if access_limited else "Listed"
        return {
            "provider": provider["name"], "subject": subject, "kind": provider["kind"], "status": status,
            "answers": "Provider access limited" if access_limited else response,
            "delist_url": provider["delist_url"] if status == "Listed" else None,
        }
    except dns.resolver.NXDOMAIN:
        return {"provider": provider["name"], "subject": subject, "kind": provider["kind"], "status": "Clean", "answers": "No listing returned", "delist_url": None}
    except dns.exception.DNSException as exc:
        return {"provider": provider["name"], "subject": subject, "kind": provider["kind"], "status": "Unknown", "answers": str(exc), "delist_url": None}


def _dnsbl_query(subject, provider):
    if provider["kind"] == "ip":
        address = ipaddress.ip_address(subject)
        if address.version != 4:
            return f"{''.join(reversed(address.exploded.replace(':', '')))}.{provider['zone']}"
        return f"{'.'.join(reversed(subject.split('.')))}.{provider['zone']}"
    return f"{subject.lower().rstrip('.')}.{provider['zone']}"


def run_blacklist_task(database, task_id, target):
    try:
        report = check_blacklists(target)
        report["local_heuristic"] = ingest_local_intelligence(database, task_id, "blacklist", report)
        result = json.dumps(report)
        status, error = "Complete", None
    except (dns.exception.DNSException, ValueError, OSError) as exc:
        status, result, error = "Failed", None, str(exc)[:1000]
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE blacklist_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?", (status, result, error, datetime.now(timezone.utc).isoformat(), task_id))


def register_blacklist_routes(app, database, db, current_user, login_required):
    @app.route("/recon/blacklist", methods=["GET", "POST"])
    @login_required
    def blacklist_check():
        if request.method == "POST":
            target = request.form.get("target", "").strip().rstrip(".")
            if not valid_dns_target(target):
                flash("Enter a valid domain, hostname, or public IP address.", "error")
            elif resolves_to_non_public_ip(target):
                flash("Private, local, reserved, and non-public targets are not allowed.", "error")
            else:
                task_id = str(uuid.uuid4())
                db().execute(
                    """INSERT INTO blacklist_tasks
                    (id, user_id, target, status, result, error, created_at, completed_at, is_private)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (task_id, current_user()["id"], target, "Running", None, None, datetime.now(timezone.utc).isoformat(), None, is_private_task(request.form)),
                )
                db().commit()
                threading.Thread(target=run_blacklist_task, args=(database, task_id, target), daemon=True).start()
                flash("Blacklist task started. It will continue while you navigate the application.", "success")
                return redirect(url_for("blacklist_check"))
        tasks = visible_tasks(db(), "blacklist_tasks", current_user()["id"])
        return render_template("blacklist.html", tasks=tasks, requested_target=request.args.get("target", "").strip())

    @app.route("/recon/blacklist/<task_id>")
    @login_required
    def view_blacklist_task(task_id):
        task = visible_task(db(), "blacklist_tasks", task_id, current_user()["id"])
        if not task:
            flash("Blacklist task not found.", "error")
            return redirect(url_for("blacklist_check"))
        report = json.loads(task["result"]) if task["result"] else {"resolved_ips": [], "checks": []}
        status_order = {"Listed": 0, "Unknown": 1, "Clean": 2}
        report["checks"].sort(key=lambda check: (status_order.get(check.get("status"), 3), check.get("provider", ""), check.get("subject", "")))
        return render_template("blacklist_task.html", task=task, report=report)

    @app.post("/recon/blacklist/<task_id>/delete")
    @login_required
    def delete_blacklist_task(task_id):
        delete_owned_task(db(), "blacklist_tasks", task_id, current_user()["id"])
        db().commit()
        flash("Blacklist task deleted.", "success")
        return redirect(url_for("blacklist_check"))

    @app.get("/recon/blacklist/<task_id>/export/<export_format>")
    @login_required
    def export_blacklist_task(task_id, export_format):
        task = visible_task(db(), "blacklist_tasks", task_id, current_user()["id"])
        if not task:
            flash("Blacklist task not found.", "error")
            return redirect(url_for("blacklist_check"))

        report = json.loads(task["result"]) if task["result"] else {"target": task["target"], "resolved_ips": [], "checks": []}
        status_order = {"Listed": 0, "Unknown": 1, "Clean": 2}
        report["checks"].sort(key=lambda check: (status_order.get(check.get("status"), 3), check.get("provider", ""), check.get("subject", "")))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

        if export_format == "json":
            export_data = dict(task)
            export_data.pop("result", None)
            export_data["report"] = report
            response = make_response(jsonify(export_data))
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-blacklist-{timestamp}.json"
            return response
        if export_format == "html":
            response = make_response(render_template("blacklist_export.html", task=task, report=report, generated_at=datetime.now(timezone.utc)))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-blacklist-{timestamp}.html"
            return response

        flash("Unsupported export format.", "error")
        return redirect(url_for("view_blacklist_task", task_id=task_id))
