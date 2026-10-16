import ipaddress
import json
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import flash, jsonify, make_response, redirect, render_template, request, url_for

from utils.dns import geolocate_result, resolves_to_non_public_ip, valid_dns_target
from utils.task_access import delete_owned_task, is_private_task, module_history, visible_task


class RdapNotFoundError(RuntimeError):
    pass


RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
COMMON_RDAP_ENDPOINTS = {
    "com": ("https://rdap.verisign.com/com/v1/",),
    "net": ("https://rdap.verisign.com/net/v1/",),
    "name": ("https://rdap.verisign.com/name/v1/",),
    "org": ("https://rdap.publicinterestregistry.org/rdap/",),
    "ink": ("https://rdap.nic.ink/",),
    "hn": ("https://rdap.nic.hn/",),
}
_rdap_bootstrap, _rdap_bootstrap_expires = {}, 0.0


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _bootstrap_domain_endpoints(target):
    global _rdap_bootstrap, _rdap_bootstrap_expires

    labels = target.lower().split(".")
    matches = [".".join(labels[offset:]) for offset in range(len(labels))]
    for suffix in matches:
        endpoints = COMMON_RDAP_ENDPOINTS.get(suffix, ())
        if endpoints:
            return list(endpoints)
    now = time.monotonic()
    if now >= _rdap_bootstrap_expires:
        try:
            query = Request(RDAP_BOOTSTRAP_URL, headers={"Accept": "application/json", "User-Agent": "Cyberseek/1.0"})
            with urlopen(query, timeout=3) as response:
                payload = json.loads(response.read().decode("utf-8"))
            _rdap_bootstrap = {
                str(suffix).lower(): tuple(str(endpoint) for endpoint in endpoints)
                for suffixes, endpoints in payload.get("services", [])
                for suffix in suffixes
                if endpoints
            }
        except (HTTPError, URLError, ValueError, TimeoutError, json.JSONDecodeError):
            pass
        _rdap_bootstrap_expires = now + 86_400
    endpoints = []
    for suffix in matches:
        endpoints.extend(_rdap_bootstrap.get(suffix, ()))
        if endpoints:
            break
    return list(dict.fromkeys(endpoints))


def run_whois_task(database, task_id, target):
    try:
        result = fetch_rdap(target)
        status, error = "Complete", None
        output = json.dumps(result)[:50000]
    except (HTTPError, URLError, ValueError, TimeoutError, RuntimeError) as exc:
        status, output, error = "Failed", None, str(exc)[:1000]
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE whois_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?",
            (status, output, error, datetime.now(timezone.utc).isoformat(), task_id))


def fetch_rdap(target):
    resource = "ip" if _is_ip(target) else "domain"
    errors = []
    not_found, attempts = 0, 0
    labels = target.split(".")
    candidates = [target] if resource == "ip" or len(labels) < 2 else [".".join(labels[offset:]) for offset in range(len(labels) - 1)]
    for candidate in candidates:
        registry_endpoints = [f"{endpoint.rstrip('/')}/{resource}/{candidate}" for endpoint in _bootstrap_domain_endpoints(candidate)] if resource == "domain" else []
        endpoints = registry_endpoints + [f"https://rdap.org/{resource}/{candidate}", f"https://rdap.net/{resource}/{candidate}"]
        for endpoint in dict.fromkeys(endpoints):
            attempts += 1
            try:
                query = Request(endpoint, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "Cyberseek/1.0"})
                with urlopen(query, timeout=8) as response:
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as exc:
                if exc.code == 404:
                    not_found += 1
                else:
                    errors.append(f"HTTP {exc.code}")
            except (URLError, ValueError, TimeoutError) as exc:
                errors.append(str(exc))
    if attempts and not_found == attempts:
        raise RdapNotFoundError("No RDAP registration record is available for this domain or IP address.")
    detail = " | ".join(dict.fromkeys(errors)) or "No RDAP service returned a usable response."
    raise RuntimeError("RDAP lookup failed: " + detail)


def format_whois_output(result):
    if not result:
        return []
    data = json.loads(result)
    event_dates = {event.get("eventAction", "").lower(): event.get("eventDate") for event in data.get("events", [])}
    registrar, contacts, phones, addresses, countries, nic_handles = [], [], [], [], [], []
    for entity in _walk_entities(data.get("entities", [])):
        roles = [role.lower() for role in entity.get("roles", [])]
        card = _vcard_properties(entity)
        handle = entity.get("handle")
        name = _card_value(card, "fn") or _card_value(card, "org") or handle or "Unknown"
        if handle:
            nic_handles.append(handle)
        if "registrar" in roles:
            registrar.append(name)
        elif roles:
            contacts.append(f"{', '.join(role.title() for role in roles)}: {name}")
        phones.extend(_card_values(card, "tel"))
        for address in _card_values(card, "adr"):
            if isinstance(address, list):
                parts = [str(item) for item in address if item]
                if parts:
                    addresses.append(", ".join(parts))
                    if len(address) > 6 and address[6]:
                        countries.append(str(address[6]))
        if entity.get("country"):
            countries.append(entity["country"])
    nameservers = ", ".join(item.get("ldhName") for item in data.get("nameservers", []) if item.get("ldhName"))
    fields = [
        ("Object", data.get("objectClassName")), ("Handle", data.get("handle")),
        ("Name", data.get("ldhName") or data.get("unicodeName") or data.get("name")),
        ("NIC Handle", ", ".join(dict.fromkeys(nic_handles))), ("Registrar", ", ".join(dict.fromkeys(registrar))),
        ("Created", event_dates.get("registration")), ("Expires", event_dates.get("expiration")),
        ("Last changed", event_dates.get("last changed") or event_dates.get("last update")),
        ("Status", ", ".join(data.get("status", []))), ("Country", ", ".join(dict.fromkeys(countries))),
        ("Contacts", "; ".join(dict.fromkeys(contacts))), ("Phone numbers", ", ".join(dict.fromkeys(str(phone) for phone in phones))),
        ("Addresses", "; ".join(dict.fromkeys(addresses))), ("Nameservers", nameservers), ("Port 43", data.get("port43")),
    ]
    return [(label, value) for label, value in fields if value]


def _walk_entities(entities):
    for entity in entities:
        yield entity
        yield from _walk_entities(entity.get("entities", []))


def _vcard_properties(entity):
    card = entity.get("vcardArray", [None, []])
    values = card[1] if len(card) > 1 else []
    result = {}
    for value in values:
        if len(value) >= 4:
            result.setdefault(value[0].lower(), []).append(value[3])
    return result


def _card_values(card, key):
    return card.get(key, [])


def _card_value(card, key):
    values = _card_values(card, key)
    return values[0] if values else None


def register_whois_routes(app, database, db, current_user, login_required):
    @app.route("/recon/whois", methods=["GET", "POST"])
    @login_required
    def whois_lookup():
        if request.method == "POST":
            target = request.form.get("target", "").strip().rstrip(".")
            if not valid_dns_target(target):
                flash("Enter a valid domain or IP address.", "error")
            elif resolves_to_non_public_ip(target):
                flash("Private, local, reserved, and non-public targets are not allowed.", "error")
            else:
                task_id = str(uuid.uuid4())
                db().execute(
                    """INSERT INTO whois_tasks
                    (id, user_id, target, status, result, error, created_at, completed_at, is_private)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (task_id, current_user()["id"], target, "Running", None, None, datetime.now(timezone.utc).isoformat(), None, is_private_task(request.form)),
                )
                db().commit()
                threading.Thread(target=run_whois_task, args=(database, task_id, target), daemon=True).start()
                flash("WHOIS task started. It will continue while you navigate the application.", "success")
                return redirect(url_for("whois_lookup"))
        return render_template(
            "whois.html", history=module_history(db(), "whois", current_user()["id"], request.args),
            requested_target=request.args.get("target", "").strip() if request.method == "GET" else "",
        )

    @app.route("/recon/whois/<task_id>")
    @login_required
    def view_whois_task(task_id):
        task = visible_task(db(), "whois_tasks", task_id, current_user()["id"])
        if not task:
            flash("WHOIS task not found.", "error")
            return redirect(url_for("whois_lookup"))
        return render_template("whois_task.html", task=task, fields=format_whois_output(task["result"]), location=geolocate_result("", task["target"]))

    @app.post("/recon/whois/<task_id>/delete")
    @login_required
    def delete_whois_task(task_id):
        delete_owned_task(db(), "whois_tasks", task_id, current_user()["id"])
        db().commit()
        flash("WHOIS task deleted.", "success")
        return redirect(url_for("whois_lookup"))

    @app.get("/recon/whois/<task_id>/export/<export_format>")
    @login_required
    def export_whois_task(task_id, export_format):
        task = visible_task(db(), "whois_tasks", task_id, current_user()["id"])
        if not task:
            flash("WHOIS task not found.", "error")
            return redirect(url_for("whois_lookup"))
        fields = format_whois_output(task["result"])
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if export_format == "json":
            data = dict(task); data["fields"] = fields
            response = make_response(jsonify(data))
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-whois-{timestamp}.json"
            return response
        if export_format == "html":
            response = make_response(render_template("whois_export.html", task=task, fields=fields, generated_at=datetime.now(timezone.utc)))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-whois-{timestamp}.html"
            return response
        flash("Unsupported export format.", "error")
        return redirect(url_for("whois_lookup"))
