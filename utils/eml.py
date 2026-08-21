import hashlib
import ipaddress
import io
import json
import os
import re
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from base64 import urlsafe_b64encode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones
from zipfile import ZIP_DEFLATED

from flask import flash, jsonify, make_response, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from utils.analysis import is_private_host
from utils.source_config import source_api_settings
from utils.task_access import delete_owned_task, is_private_task, visible_task, visible_tasks


DEFAULT_EMAIL_TIMEZONE = "America/Tegucigalpa"
EMAIL_TIMEZONES = {name: name for name in sorted(available_timezones())}
if not EMAIL_TIMEZONES:
    EMAIL_TIMEZONES = {DEFAULT_EMAIL_TIMEZONE: DEFAULT_EMAIL_TIMEZONE, "UTC": "UTC"}
EMAIL_TIMEZONES.setdefault(DEFAULT_EMAIL_TIMEZONE, DEFAULT_EMAIL_TIMEZONE)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
IP_PATTERN = re.compile(r"(?<![0-9A-Za-z])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.%]+)")
SPF_STATUS_PATTERN = re.compile(r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)


class _EmailPreviewSanitizer(HTMLParser):
    allowed_tags = {"a", "b", "blockquote", "br", "code", "div", "em", "h1", "h2", "h3", "h4", "hr", "i", "li", "ol", "p", "pre", "span", "strong", "table", "tbody", "td", "th", "thead", "tr", "u", "ul"}
    void_tags = {"br", "hr"}
    ignored_tags = {"embed", "form", "iframe", "img", "object", "script", "style", "svg", "video"}
    ignored_void_tags = {"embed", "img"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.ignored_tags:
            if tag not in self.ignored_void_tags:
                self.ignored_depth += 1
            return
        if self.ignored_depth:
            return
        if tag not in self.allowed_tags:
            return
        attributes = ""
        if tag == "a":
            href = next((value for name, value in attrs if name.lower() == "href"), "")
            if href and urlparse(href).scheme in {"http", "https", "mailto"}:
                attributes = f' href="{escape(href, quote=True)}"'
        self.output.append(f"<{tag}{attributes}>")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.ignored_tags:
            if tag not in self.ignored_void_tags:
                self.ignored_depth = max(0, self.ignored_depth - 1)
            return
        if self.ignored_depth:
            return
        if tag in self.allowed_tags and tag not in self.void_tags:
            self.output.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.ignored_depth:
            self.output.append(escape(data))


def _as_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _email_preview(html_body, plain_body):
    html_body, plain_body = _as_text(html_body), _as_text(plain_body)
    fallback = f"<pre>{escape(plain_body or 'No readable message body was found.')}</pre>"
    if not html_body:
        return fallback
    try:
        sanitizer = _EmailPreviewSanitizer()
        sanitizer.feed(html_body)
        sanitizer.close()
        return "".join(sanitizer.output) or fallback
    except (TypeError, ValueError):
        return fallback
MAX_REPUTATION_ITEMS = 12


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _normalise_date(value, timezone_name):
    if not value:
        return {"original": "Unavailable", "normalized": "Unavailable"}
    try:
        try:
            moment = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        normalized = moment.astimezone(ZoneInfo(timezone_name))
        return {"original": value, "normalized": normalized.strftime("%Y-%m-%d %H:%M:%S %Z")}
    except (TypeError, ValueError, IndexError, ZoneInfoNotFoundError):
        return {"original": value, "normalized": "Unable to normalize"}


def _format_task_timestamp(value, timezone_name):
    if not value:
        return "Unavailable"
    try:
        moment = datetime.fromisoformat(value)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d %H:%M:%S %Z")
    except (TypeError, ValueError, ZoneInfoNotFoundError):
        return "Unavailable"


def _extract_urls(text):
    return list(dict.fromkeys(match.rstrip(".,;:!?)\]") for match in URL_PATTERN.findall(text or "")))[:MAX_REPUTATION_ITEMS]


def _attachment_metadata(filename, content_type, data):
    extension = Path(filename or "").suffix.lower().lstrip(".")
    return {
        "filename": filename or "unnamed attachment", "content_type": content_type or "application/octet-stream",
        "extension": extension or "Unavailable", "size": len(data), "sha256": _sha256(data),
        "sha1": hashlib.sha1(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
    }


def _attachment_bytes(path, filename, digest):
                                                                                   
    if filename.lower().endswith(".msg"):
        try:
            import extract_msg
        except ImportError as exc:
            raise ValueError("MSG parsing requires the extract-msg dependency.") from exc
        message = extract_msg.Message(str(path))
        try:
            for attachment in message.attachments:
                data = attachment.data
                if isinstance(data, str):
                    data = data.encode("utf-8", "replace")
                data = data or b""
                if _sha256(data) == digest:
                    return secure_filename(attachment.longFilename or attachment.shortFilename or "attachment.bin"), data
        finally:
            message.close()
    else:
        with Path(path).open("rb") as source:
            message = BytesParser(policy=policy.default).parse(source)
        for part in message.walk():
            if part.is_multipart():
                continue
            if part.get_content_disposition() == "attachment" or part.get_filename():
                data = part.get_payload(decode=True) or b""
                if _sha256(data) == digest:
                    return secure_filename(part.get_filename() or "attachment.bin"), data
    raise ValueError("The requested attachment was not found in the original email.")


def _authentication_value(message, mechanism):
                                                                                     
    mechanism = mechanism.lower()
    if mechanism == "spf":
        received_spf = message.get("Received-SPF")
        if received_spf:
            return received_spf
    if mechanism == "dkim":
        signature = message.get("DKIM-Signature")
        if signature:
            return signature
    for header_name in ("Authentication-Results", "ARC-Authentication-Results"):
        for value in message.get_all(header_name, []):
            if re.search(rf"\b{re.escape(mechanism)}\s*=", value, re.IGNORECASE):
                return value
    return None


def _spf_status(value):
    if not value:
        return "Not present"
    match = SPF_STATUS_PATTERN.search(value)
    if match:
        return match.group(1).title()
    first_token = str(value).strip().split(None, 1)[0].lower() if str(value).strip() else ""
    if first_token in {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}:
        return first_token.title()
    return "Present"


def _ensure_spf_rows(report):
                                                                                       
    headers = report.get("headers", [])
    by_name = {item.get("name"): item.get("value") for item in headers}
    spf_value = by_name.get("SPF", "Not present")
    if "SPF" not in by_name:
        headers.append({"name": "SPF", "value": spf_value})
    if "SPF status" not in by_name:
        headers.append({"name": "SPF status", "value": _spf_status(spf_value if spf_value != "Not present" else "")})
    report["headers"] = headers
    return report


def _received_date(dates):
    return next((item for item in dates if item.get("name") == "Received"), dates[0] if dates else {"original": "Unavailable", "normalized": "Unavailable"})


def _sending_ip(received_headers):
                                                                                     
    for header in received_headers or []:
        for candidate in IP_PATTERN.findall(header or ""):
            try:
                if ipaddress.ip_address(candidate).is_global:
                    return candidate
            except ValueError:
                continue
    return ""


def _parse_eml(path, timezone_name):
    with Path(path).open("rb") as source:
        message = BytesParser(policy=policy.default).parse(source)
    attachments, plain_bodies, html_bodies = [], [], []
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if disposition == "attachment" or filename:
            attachment = _attachment_metadata(filename, part.get_content_type(), payload)
            attachment.update({
                "content_disposition": disposition or "Unavailable", "content_id": part.get("Content-ID") or "Unavailable",
                "content_description": part.get("Content-Description") or "Unavailable", "transfer_encoding": part.get("Content-Transfer-Encoding") or "Unavailable",
            })
            attachments.append(attachment)
        elif part.get_content_type() in {"text/plain", "text/html"}:
            try:
                body = payload.decode(part.get_content_charset() or "utf-8", "replace")
            except (LookupError, UnicodeDecodeError):
                body = payload.decode("utf-8", "replace")
            (html_bodies if part.get_content_type() == "text/html" else plain_bodies).append(body)
    received_headers = message.get_all("Received", [])
    date_headers = [{"name": "Date", **_normalise_date(message.get("Date"), timezone_name)}]
    for value in received_headers:
        date_headers.append({"name": "Received", **_normalise_date(value.rsplit(";", 1)[-1].strip(), timezone_name)})
    spf_header = _authentication_value(message, "spf")
    headers = [
        ("From", message.get("From")), ("Reply-To", message.get("Reply-To")), ("To", message.get("To")),
        ("Cc", message.get("Cc")), ("Subject", message.get("Subject")), ("Message-ID", message.get("Message-ID")),
        ("Return-Path", message.get("Return-Path")), ("Authentication-Results", message.get("Authentication-Results")),
        ("SPF", spf_header or "Not present"), ("SPF status", _spf_status(spf_header)), ("DMARC", _authentication_value(message, "dmarc")),
        ("DKIM", _authentication_value(message, "dkim")),
    ]
    plain_body, html_body = "\n".join(plain_bodies), "\n".join(html_bodies)
    return {"headers": [{"name": name, "value": value} for name, value in headers if value], "dates": date_headers, "body": "\n".join((plain_body, html_body)), "preview_html": _email_preview(html_body, plain_body), "attachments": attachments, "sender_ip": _sending_ip(received_headers)}


def _parse_msg(path, timezone_name):
    try:
        import extract_msg
    except ImportError as exc:
        raise ValueError("MSG parsing requires the extract-msg dependency. Install project requirements and retry.") from exc
    message = extract_msg.Message(str(path))
    try:
        attachments = []
        for attachment in message.attachments:
            data = attachment.data
            if isinstance(data, str):
                data = data.encode("utf-8", "replace")
            parsed_attachment = _attachment_metadata(attachment.longFilename or attachment.shortFilename, "application/octet-stream", data or b"")
            parsed_attachment.update({"content_disposition": "Attachment", "content_id": "Unavailable", "content_description": "Unavailable", "transfer_encoding": "Unavailable"})
            attachments.append(parsed_attachment)
        raw_headers = _as_text(getattr(message, "headerText", ""))
        source_headers = BytesParser(policy=policy.default).parsebytes(raw_headers.encode("utf-8", "replace")) if raw_headers else None
        headers = [
            ("From", message.sender), ("To", message.to), ("Cc", message.cc), ("Subject", message.subject),
            ("Reply-To", getattr(message, "replyTo", None)), ("Message-ID", getattr(message, "messageId", None)),
        ]
        if source_headers:
            spf_header = _authentication_value(source_headers, "spf")
            headers.extend([
                ("Authentication-Results", source_headers.get("Authentication-Results")),
                ("SPF", spf_header or "Not present"), ("SPF status", _spf_status(spf_header)), ("DMARC", _authentication_value(source_headers, "dmarc")),
                ("DKIM", _authentication_value(source_headers, "dkim")),
            ])
        else:
            headers.extend([("SPF", "Not present"), ("SPF status", "Not present")])
        received_headers = source_headers.get_all("Received", []) if source_headers else []
        date_value = str(message.date or "")
        plain_body = _as_text(message.body)
        html_body = _as_text(getattr(message, "htmlBody", None))
        return {"headers": [{"name": name, "value": value} for name, value in headers if value], "dates": [{"name": "Date", **_normalise_date(date_value, timezone_name)}], "body": "\n".join((plain_body, html_body)), "preview_html": _email_preview(html_body, plain_body), "attachments": attachments, "sender_ip": _sending_ip(received_headers)}
    finally:
        message.close()


def _vt_lookup(value, kind):
    key = source_api_settings().get("virustotal_api_key", "").strip()
    if not key:
        return {"state": "Not configured", "verdict": "Unknown", "detail": "Configure a VirusTotal API key in Source APIs."}
    if kind == "url":
        resource = "urls/" + urlsafe_b64encode(value.encode()).decode().rstrip("=")
    elif kind == "domain":
        resource = "domains/" + value
    else:
        resource = "files/" + value
    try:
        query = Request(f"https://www.virustotal.com/api/v3/{resource}", headers={"x-apikey": key, "Accept": "application/json"})
        with urlopen(query, timeout=7) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if not stats:
            return {"state": "Unavailable", "verdict": "Unknown", "detail": "VirusTotal returned no completed cached verdict."}
        malicious, suspicious, clean = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)), int(stats.get("harmless", 0))
        verdict = "Malicious" if malicious else "Suspicious" if suspicious else "Clean"
        return {"state": "Complete", "verdict": verdict, "malicious": malicious, "suspicious": suspicious, "clean": clean, "detail": "Cached VirusTotal reputation."}
    except HTTPError as exc:
        return {"state": "Unavailable", "verdict": "Unknown", "detail": f"VirusTotal returned HTTP {exc.code}."}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"state": "Unavailable", "verdict": "Unknown", "detail": f"VirusTotal lookup unavailable: {str(exc)[:160]}"}


def _sender_domain(headers):
    sender = next((item["value"] for item in headers if item["name"] == "From"), "")
    address = parseaddr(sender)[1].lower()
    domain = address.rsplit("@", 1)[-1] if "@" in address else ""
    return address, domain


def run_eml_analysis(path, filename, timezone_name):
    started_at = datetime.now(timezone.utc)
    parser = _parse_msg if filename.lower().endswith(".msg") else _parse_eml
    parsed = parser(path, timezone_name)
    sender, sender_domain = _sender_domain(parsed["headers"])
    urls = [{"url": value} for value in _extract_urls(parsed["body"])]
    attachments = parsed["attachments"][:MAX_REPUTATION_ITEMS]
    lookups = []
    if sender_domain and not is_private_host(sender_domain):
        lookups.append(("sender", sender_domain, "domain"))
    lookups.extend(("url", item["url"], "url") for item in urls)
    lookups.extend(("attachment", item["sha256"], "file") for item in attachments)
    results = {}
    executor = ThreadPoolExecutor(max_workers=min(8, max(1, len(lookups))))
    futures = {executor.submit(_vt_lookup, value, kind): (category, value) for category, value, kind in lookups}
    done, pending = wait(futures, timeout=15)
    for future in done:
        results[futures[future]] = future.result()
    for future in pending:
        future.cancel()
        results[futures[future]] = {"state": "Timed out", "verdict": "Unknown", "detail": "VirusTotal lookup exceeded the collection window."}
    executor.shutdown(wait=False, cancel_futures=True)
    for item in urls:
        item["reputation"] = results.get(("url", item["url"]), {"state": "Unavailable", "verdict": "Unknown", "detail": "Not queried"})
    for item in attachments:
        item["reputation"] = results.get(("attachment", item["sha256"]), {"state": "Unavailable", "verdict": "Unknown", "detail": "Not queried"})
    sender_reputation = results.get(("sender", sender_domain), {"state": "Unavailable", "verdict": "Unknown", "detail": "No public sender domain was available."})
    received_date = _received_date(parsed["dates"])
    return {
        "filename": filename, "timezone": timezone_name,
        "analysis_started": started_at.astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "analysis_completed": datetime.now(timezone.utc).astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "sender": sender, "sender_domain": sender_domain or "Unavailable", "sender_reputation": sender_reputation,
        "headers": parsed["headers"], "dates": parsed["dates"], "received_date": received_date, "sender_ip": parsed.get("sender_ip", ""), "preview_html": parsed.get("preview_html", ""),
        "attachments": attachments, "urls": urls,
    }


def register_eml_routes(app, database, db, current_user, login_required, upload_dir):
    upload_dir = Path(upload_dir)

    def worker(task_id, path, filename, timezone_name):
        try:
            result, status, error = json.dumps(run_eml_analysis(path, filename, timezone_name)), "Complete", None
        except Exception as exc:
            result, status, error = None, "Failed", str(exc)[:1000]
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE eml_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?", (status, result, error, datetime.now(timezone.utc).isoformat(), task_id))

    def expire_stalled_eml_tasks():
        cutoff = datetime.now(timezone.utc).timestamp() - 60
        db().execute(
            """UPDATE eml_tasks SET status = 'Failed', error = 'The email analysis exceeded the collection window.', completed_at = ?
            WHERE status = 'Running' AND CAST(strftime('%s', created_at) AS INTEGER) < ?""",
            (datetime.now(timezone.utc).isoformat(), cutoff),
        )
        db().commit()

    @app.route("/analysis/eml", methods=["GET", "POST"])
    @login_required
    def eml_analysis():
        expire_stalled_eml_tasks()
        if request.method == "POST":
            upload = request.files.get("email_file")
            timezone_name = request.form.get("timezone", DEFAULT_EMAIL_TIMEZONE)
            filename = secure_filename(upload.filename) if upload and upload.filename else ""
            if not filename or Path(filename).suffix.lower() not in {".eml", ".msg"}:
                flash("Upload an .eml or .msg email file.", "error")
            elif timezone_name not in EMAIL_TIMEZONES:
                flash("Select a supported time zone.", "error")
            else:
                upload_dir.mkdir(parents=True, exist_ok=True)
                task_id = str(uuid.uuid4())
                stored = upload_dir / f"{task_id}_{filename}"
                upload.save(stored)
                db().execute("INSERT INTO eml_tasks (id, user_id, filename, stored_path, timezone, status, result, error, created_at, completed_at, is_private) VALUES (?, ?, ?, ?, ?, 'Running', NULL, NULL, ?, NULL, ?)", (task_id, current_user()["id"], filename, str(stored), timezone_name, datetime.now(timezone.utc).isoformat(), is_private_task(request.form)))
                db().commit()
                threading.Thread(target=worker, args=(task_id, str(stored), filename, timezone_name), daemon=True).start()
                flash("Email analysis started. It will continue while you navigate the application.", "success")
                return redirect(url_for("eml_analysis"))
        return render_template("eml.html", tasks=visible_tasks(db(), "eml_tasks", current_user()["id"]), timezones=EMAIL_TIMEZONES)

    @app.get("/analysis/eml/<task_id>")
    @login_required
    def view_eml_analysis(task_id):
        expire_stalled_eml_tasks()
        task = visible_task(db(), "eml_tasks", task_id, current_user()["id"])
        if not task:
            flash("Email analysis task not found.", "error")
            return redirect(url_for("eml_analysis"))
        report = _ensure_spf_rows(json.loads(task["result"])) if task["result"] else None
        if report is not None and (not report.get("preview_html") or not report.get("sender_ip")):
            try:
                parser = _parse_msg if task["filename"].lower().endswith(".msg") else _parse_eml
                parsed = parser(task["stored_path"], task["timezone"])
                report.setdefault("preview_html", parsed.get("preview_html", ""))
                report["sender_ip"] = parsed.get("sender_ip", report.get("sender_ip", ""))
            except (OSError, ValueError, RuntimeError):
                if not report.get("preview_html"):
                    report["preview_html"] = _email_preview(report.get("body", ""), "")
        return render_template("eml_task.html", task=task, report=report, timezones=EMAIL_TIMEZONES)

    @app.get("/analysis/eml/<task_id>/attachments/<attachment_sha256>/download")
    @login_required
    def download_eml_attachment(task_id, attachment_sha256):
        task = visible_task(db(), "eml_tasks", task_id, current_user()["id"])
        if not task or not re.fullmatch(r"[a-fA-F0-9]{64}", attachment_sha256):
            flash("Attachment not found.", "error")
            return redirect(url_for("eml_analysis"))
        try:
            attachment_name, data = _attachment_bytes(task["stored_path"], task["filename"], attachment_sha256.lower())
            import pyzipper
            archive_data = io.BytesIO()
            with pyzipper.AESZipFile(archive_data, "w", compression=ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
                archive.setpassword(b"infected")
                archive.writestr(attachment_name, data)
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            flash(f"Protected attachment download is unavailable: {str(exc)[:180]}", "error")
            return redirect(url_for("view_eml_analysis", task_id=task_id))
        response = make_response(archive_data.getvalue())
        response.headers["Content-Type"] = "application/zip"
        response.headers["Content-Disposition"] = f'attachment; filename="{secure_filename(Path(attachment_name).stem) or "attachment"}.zip"'
        response.headers["Content-Length"] = str(archive_data.tell())
        return response

    @app.post("/analysis/eml/<task_id>/timezone")
    @login_required
    def update_eml_timezone(task_id):
        task = visible_task(db(), "eml_tasks", task_id, current_user()["id"])
        timezone_name = request.form.get("timezone", "")
        if not task or task["user_id"] != current_user()["id"]:
            flash("Only the task owner can change its report time zone.", "error")
        elif timezone_name not in EMAIL_TIMEZONES:
            flash("Select a supported time zone.", "error")
        else:
            report = json.loads(task["result"]) if task["result"] else None
            if report:
                report["timezone"] = timezone_name
                report["dates"] = [
                    {"name": item.get("name", "Date"), **_normalise_date(item.get("original"), timezone_name)}
                    for item in report.get("dates", [])
                ]
                report["received_date"] = _received_date(report["dates"])
                report["analysis_started"] = _format_task_timestamp(task["created_at"], timezone_name)
                report["analysis_completed"] = _format_task_timestamp(task["completed_at"], timezone_name)
                db().execute("UPDATE eml_tasks SET timezone = ?, result = ? WHERE id = ?", (timezone_name, json.dumps(report), task_id))
            else:
                db().execute("UPDATE eml_tasks SET timezone = ? WHERE id = ?", (timezone_name, task_id))
            db().commit()
            flash("Report time zone updated.", "success")
        return redirect(url_for("view_eml_analysis", task_id=task_id))

    @app.get("/analysis/eml/<task_id>/export/json", defaults={"export_format": "json"})
    @app.get("/analysis/eml/<task_id>/export/<export_format>")
    @login_required
    def export_eml_analysis(task_id, export_format):
        task = visible_task(db(), "eml_tasks", task_id, current_user()["id"])
        if not task or not task["result"]:
            flash("Email analysis report not found.", "error")
            return redirect(url_for("eml_analysis"))
        report = _ensure_spf_rows(json.loads(task["result"]))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if export_format == "html":
            response = make_response(render_template("eml_export.html", task=task, report=report, generated_at=datetime.now(timezone.utc)))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-email-{timestamp}.html"
            return response
        if export_format != "json":
            flash("Unsupported export format.", "error")
            return redirect(url_for("view_eml_analysis", task_id=task_id))
        payload = dict(task)
        payload.pop("stored_path", None)
        payload["report"] = report
        response = make_response(jsonify(payload))
        response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-email-{timestamp}.json"
        return response

    @app.post("/analysis/eml/<task_id>/delete")
    @login_required
    def delete_eml_analysis(task_id):
        task = visible_task(db(), "eml_tasks", task_id, current_user()["id"])
        deleted = delete_owned_task(db(), "eml_tasks", task_id, current_user()["id"])
        db().commit()
        if deleted.rowcount and task:
            Path(task["stored_path"]).unlink(missing_ok=True)
            flash("Email analysis deleted.", "success")
        return redirect(url_for("eml_analysis"))
