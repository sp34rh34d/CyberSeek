import re
import sqlite3
import threading
import uuid
from math import asinh, pi, tan
from datetime import datetime, timezone
from ipaddress import ip_address
from json import loads
from urllib.error import URLError
from urllib.request import urlopen

import dns.exception
import dns.resolver
from flask import Response, flash, jsonify, make_response, redirect, render_template, request, url_for

from utils.task_access import delete_owned_task, is_private_task, visible_task, visible_tasks


ALLOWED_RECORD_TYPES = {"A", "AAAA", "TXT", "NS", "CNAME", "PTR", "MX", "SOA", "DS", "ALL"}
RECORD_TYPE_ORDER = {record_type: position for position, record_type in enumerate(("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "DS", "PTR"))}


def valid_dns_target(value):
    return bool(re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", value))


def resolves_to_non_public_ip(value):
    if value.lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return not ip_address(value).is_global
    except ValueError:
        pass
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(value, record_type, raise_on_no_answer=False)
            if any(not ip_address(record.to_text()).is_global for record in answers):
                return True
        except dns.exception.DNSException:
            continue
    return False


def geolocate_result(result, target=None):
    candidate = next((item for item in re.findall(r"[0-9A-Fa-f:.]+", result or "") if _is_public_ip(item)), None)
    if not candidate and target and _is_public_ip(target):
        candidate = target
    elif not candidate and target:
        try:
            answers = dns.resolver.resolve(target, "A", lifetime=5)
            candidate = next((record.to_text() for record in answers if _is_public_ip(record.to_text())), None)
        except dns.exception.DNSException:
            pass
    if not candidate:
        return None
    providers = (
        (f"https://ipapi.co/{candidate}/json/", "latitude", "longitude", ("city", "region", "country_name")),
        (f"https://ipwho.is/{candidate}", "latitude", "longitude", ("city", "region", "country")),
    )
    for endpoint, latitude, longitude, label_keys in providers:
        try:
            with urlopen(endpoint, timeout=6) as response:
                location = loads(response.read().decode("utf-8"))
            if location.get(latitude) is None or location.get(longitude) is None:
                continue
            country = location.get("country_name") or location.get("country")
            state = location.get("region") or location.get("region_name") or location.get("state")
            city = location.get("city")
            return {"ip": candidate, "latitude": location[latitude], "longitude": location[longitude],
                "country": country, "state": state, "city": city,
                "label": ", ".join(part for part in (city, state, country) if part)}
        except (URLError, ValueError, TimeoutError):
            continue
    return None


def _is_public_ip(value):
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def format_dns_output(result, fallback_type):
    groups, current_type, records = [], fallback_type, []
    for line in (result or "").splitlines():
        if line.startswith("; "):
            if records:
                groups.append({"record_type": current_type, "records": records})
            current_type, records = line[2:].strip(), []
        elif line.strip():
            records.append(line.strip())
    if records:
        groups.append({"record_type": current_type, "records": records})
    return sorted(groups, key=lambda group: RECORD_TYPE_ORDER.get(group["record_type"], len(RECORD_TYPE_ORDER)))


def run_dns_task(database, task_id, domain, record_type):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 8
        resolver.lifetime = 20
        if record_type == "ALL":
            lines = []
            for query_type in sorted(ALLOWED_RECORD_TYPES - {"ALL"}):
                try:
                    answers = resolver.resolve(domain, query_type, raise_on_no_answer=False)
                    records = [record.to_text() for record in answers]
                    if records:
                        lines.append(f"; {query_type}\n" + "\n".join(records))
                except dns.exception.DNSException:
                    continue
            output = "\n\n".join(lines)
        else:
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            output = "\n".join(record.to_text() for record in answers)
        status, error = "Complete", None
        if not output:
            output = "No DNS records returned."
    except (dns.exception.DNSException, ValueError) as exc:
        status, output, error = "Failed", None, str(exc)[:1000]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE dns_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?",
            (status, output, error, datetime.now(timezone.utc).isoformat(), task_id),
        )


def register_dns_routes(app, database, db, current_user, login_required):
    @app.route("/recon/dns", methods=["GET", "POST"])
    @login_required
    def dns_queries():
        if request.method == "POST":
            domain = request.form.get("domain", "").strip().rstrip(".")
            record_type = request.form.get("record_type", "A").upper()
            if not valid_dns_target(domain) or record_type not in ALLOWED_RECORD_TYPES:
                flash("Enter a valid DNS target and record type.", "error")
            elif resolves_to_non_public_ip(domain):
                flash("Private, local, reserved, and non-public DNS targets are not allowed.", "error")
            else:
                task_id = str(uuid.uuid4())
                db().execute(
                    """INSERT INTO dns_tasks
                    (id, user_id, domain, record_type, status, result, error, created_at, completed_at, is_private)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (task_id, current_user()["id"], domain, record_type, "Running", None, None, datetime.now(timezone.utc).isoformat(), None, is_private_task(request.form)),
                )
                db().commit()
                threading.Thread(target=run_dns_task, args=(database, task_id, domain, record_type), daemon=True).start()
                flash("DNS task started. It will continue while you navigate the application.", "success")
                return redirect(url_for("dns_queries"))
        tasks = visible_tasks(db(), "dns_tasks", current_user()["id"])
        return render_template("dns.html", tasks=tasks)

    @app.route("/recon/dns/<task_id>")
    @login_required
    def view_dns_task(task_id):
        task = visible_task(db(), "dns_tasks", task_id, current_user()["id"])
        if not task:
            flash("DNS task not found.", "error")
            return redirect(url_for("dns_queries"))
        return render_template(
            "dns_task.html", task=task, location=geolocate_result(task["result"], task["domain"]),
            record_groups=format_dns_output(task["result"], task["record_type"]),
        )

    @app.post("/recon/dns/<task_id>/delete")
    @login_required
    def delete_dns_task(task_id):
        delete_owned_task(db(), "dns_tasks", task_id, current_user()["id"])
        db().commit()
        flash("DNS task deleted.", "success")
        return redirect(url_for("dns_queries"))

    @app.get("/recon/dns/<task_id>/export/<export_format>")
    @login_required
    def export_dns_task(task_id, export_format):
        task = visible_task(db(), "dns_tasks", task_id, current_user()["id"])
        if not task:
            flash("DNS task not found.", "error")
            return redirect(url_for("dns_queries"))
        groups = format_dns_output(task["result"], task["record_type"])
        location = geolocate_result(task["result"], task["domain"])
        export_data = dict(task)
        export_data["record_groups"] = groups
        export_data["network_location"] = location
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if export_format == "json":
            response = make_response(jsonify(export_data))
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-dns-{timestamp}.json"
            return response
        if export_format == "html":
            response = make_response(render_template("dns_export.html", task=task, groups=groups, location=location, generated_at=datetime.now(timezone.utc)))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-dns-{timestamp}.html"
            return response
        flash("Unsupported export format.", "error")
        return redirect(url_for("dns_queries"))
