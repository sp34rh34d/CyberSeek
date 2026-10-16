import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import flash, redirect, render_template, request, url_for

from utils.task_access import delete_owned_task, is_private_task, module_history, visible_task


EMAIL_PATTERN = re.compile(r"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


def _breach_entries(payload):
    exposed = payload.get("ExposedBreaches") or payload.get("exposedBreaches") or {}
    entries = exposed.get("breaches_details", []) if isinstance(exposed, dict) else exposed if isinstance(exposed, list) else []
    result = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("breach") or entry.get("breachID") or entry.get("name")
        if name:
            year = str(entry.get("xposed_date") or entry.get("breachedDate") or entry.get("breached_date") or entry.get("breach_year") or "")[:10]
            result.append({"name": str(name), "year": year[:4] if year else "Unavailable"})
    return sorted({item["name"]: item for item in result}.values(), key=lambda item: item["name"].lower())


def check_email_exposure(email):
                                                                                
    endpoint = "https://api.xposedornot.com/v1/breach-analytics?" + urlencode({"email": email})
    try:
        with urlopen(Request(endpoint, headers={"Accept": "application/json", "User-Agent": "Cyberseek/1.0"}), timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        breaches = _breach_entries(payload)
        return {
            "state": "Exposed" if breaches else "Clean", "query_type": "email", "email": email, "breaches": breaches,
            "detail": f"Found in {len(breaches)} known data breach{'es' if len(breaches) != 1 else ''}." if breaches else "No known data breach was returned for this address.",
        }
    except HTTPError as exc:
        if exc.code == 404:
            return {"state": "Clean", "query_type": "email", "email": email, "breaches": [], "detail": "No known data breach was returned for this address."}
        return {"state": "Unavailable", "query_type": "email", "email": email, "breaches": [], "detail": f"Email exposure lookup returned HTTP {exc.code}."}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return {"state": "Unavailable", "query_type": "email", "email": email, "breaches": [], "detail": "Email exposure lookup was unavailable."}


def run_email_exposure_task(database, task_id, email):
    try:
        report = check_email_exposure(email)
        status, error = "Complete", None
    except Exception as exc:
        report, status, error = None, "Failed", str(exc)[:1000]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE email_exposure_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?",
            (status, json.dumps(report) if report else None, error, datetime.now(timezone.utc).isoformat(), task_id),
        )


def register_email_exposure_routes(app, database, db, current_user, login_required):
    @app.route("/monitoring/email-exposure", methods=["GET", "POST"])
    @login_required
    def email_exposure():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            if not EMAIL_PATTERN.fullmatch(email):
                flash("Enter a valid email address.", "error")
                return redirect(url_for("email_exposure"))
            task_id = str(uuid.uuid4())
            db().execute(
                """INSERT INTO email_exposure_tasks
                (id, user_id, email, status, result, error, created_at, completed_at, is_private)
                VALUES (?, ?, ?, 'Running', NULL, NULL, ?, NULL, ?)""",
                (task_id, current_user()["id"], email, datetime.now(timezone.utc).isoformat(), is_private_task(request.form)),
            )
            db().commit()
            threading.Thread(target=run_email_exposure_task, args=(database, task_id, email), daemon=True).start()
            flash("Email exposure task started. It will continue while you navigate the application.", "success")
            return redirect(url_for("email_exposure"))
        return render_template(
            "email_exposure.html", history=module_history(db(), "email_exposure", current_user()["id"], request.args),
            requested_email=request.args.get("email", "").strip() if request.method == "GET" else "",
        )

    @app.get("/monitoring/email-exposure/<task_id>")
    @login_required
    def view_email_exposure(task_id):
        task = visible_task(db(), "email_exposure_tasks", task_id, current_user()["id"])
        if not task:
            flash("Email exposure task not found.", "error")
            return redirect(url_for("email_exposure"))
        try:
            report = json.loads(task["result"]) if task["result"] else None
        except json.JSONDecodeError:
            report = None
        return render_template("email_exposure_task.html", task=task, report=report)

    @app.post("/monitoring/email-exposure/<task_id>/delete")
    @login_required
    def delete_email_exposure(task_id):
        delete_owned_task(db(), "email_exposure_tasks", task_id, current_user()["id"])
        db().commit()
        flash("Email exposure task deleted.", "success")
        return redirect(url_for("email_exposure"))
