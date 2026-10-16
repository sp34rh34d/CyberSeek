import os
import ipaddress
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from utils.blacklist import register_blacklist_routes
from utils.dns import register_dns_routes
from utils.spf import register_spf_routes
from utils.source_config import save_source_api_settings, source_api_settings
from utils.service_config import service_settings
from utils.reputation import register_reputation_routes
from utils.surface import register_surface_routes, start_surface_scheduler
from utils.live_url import register_live_url_routes
from utils.local_heuristics import backfill_local_intelligence, init_local_heuristics
from utils.eml import register_eml_routes
from utils.email_exposure import register_email_exposure_routes
from utils.file_scan import register_file_scan_routes
from utils.modules import ADMIN_ITEMS, ICONS, MODULES, navigation, rerun_args
from utils.task_access import add_task_visibility_columns, recover_interrupted_tasks
from utils.uploads import harden_upload_dir, start_upload_retention
from utils.workspace import init_workspace, register_workspace_routes
from utils.two_factor import create_secret, decrypt_secret, encrypt_secret, provisioning_uri, qr_data_uri, valid_code
from utils.whois import register_whois_routes

SOURCE_DIR = Path(__file__).resolve().parent
RESOURCE_DIR = SOURCE_DIR if (SOURCE_DIR / "templates").is_dir() else Path(str(files("cyberseek")))
BASE_DIR = Path(os.getenv("CYBERSEEK_HOME") or SOURCE_DIR).resolve()
load_dotenv(BASE_DIR / ".env")
SERVICE_SETTINGS = service_settings()
DATABASE = BASE_DIR / "instance" / "cyberseek.db"
UPLOAD_DIR = BASE_DIR / "uploads"
LOGIN_FAILURE_LIMIT = 3
LOGIN_FAILURE_WINDOW = timedelta(minutes=15)
INITIAL_IP_QUARANTINE = timedelta(minutes=2)
QUARANTINE_INCREMENT = timedelta(minutes=5)
CSRF_SESSION_KEY = "csrf_token"


LOOPBACK_PROXY_IPS = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}

app = Flask(__name__, template_folder=str(RESOURCE_DIR / "templates"), static_folder=str(RESOURCE_DIR / "static"))
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_urlsafe(48),
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", 100 * 1024 * 1024)),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SERVICE_SETTINGS["PERMANENT_SESSION_LIFETIME"]),
    SESSION_COOKIE_SECURE=SERVICE_SETTINGS["SESSION_COOKIE_SECURE"],
    SESSION_COOKIE_HTTPONLY=SERVICE_SETTINGS["SESSION_COOKIE_HTTPONLY"],
    SESSION_COOKIE_SAMESITE=SERVICE_SETTINGS["SESSION_COOKIE_SAMESITE"],
    WTF_CSRF_SSL_STRICT=SERVICE_SETTINGS["WTF_CSRF_SSL_STRICT"],
)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection:
        connection.close()


def init_db():
    DATABASE.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DATABASE) as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_uuid TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                totp_secret TEXT,
                totp_pending_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dns_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                client_name TEXT NOT NULL DEFAULT 'Unassigned',
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS whois_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS blacklist_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS spf_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                sender_ip TEXT,
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS reputation_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                engine TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS live_url_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                user_agent TEXT NOT NULL DEFAULT 'firefox',
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS eml_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                engine TEXT NOT NULL DEFAULT 'local',
                timezone TEXT NOT NULL DEFAULT 'America/Tegucigalpa',
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS file_scan_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                analysis_mode TEXT NOT NULL DEFAULT 'static',
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS surface_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT 'domain',
                interval_minutes INTEGER NOT NULL,
                sources TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                progress_items TEXT NOT NULL DEFAULT '[]',
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_run_at TEXT,
                next_run_at TEXT NOT NULL,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS surface_ip_cache (
                ip_address TEXT PRIMARY KEY,
                country TEXT NOT NULL,
                owner TEXT NOT NULL,
                isp TEXT NOT NULL,
                cached_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS email_exposure_tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                is_private INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS login_ip_protection (
                ip_address TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lockout_level INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_failed_at TEXT NOT NULL
            );
        """)
        init_local_heuristics(connection)
        add_task_visibility_columns(connection)
        live_url_columns = {row[1] for row in connection.execute("PRAGMA table_info(live_url_tasks)")}
        if "user_agent" not in live_url_columns:
            connection.execute("ALTER TABLE live_url_tasks ADD COLUMN user_agent TEXT NOT NULL DEFAULT 'firefox'")
        file_scan_columns = {row[1] for row in connection.execute("PRAGMA table_info(file_scan_tasks)")}
        if "engine" not in file_scan_columns:
            connection.execute("ALTER TABLE file_scan_tasks ADD COLUMN engine TEXT NOT NULL DEFAULT 'local'")
        if "analysis_mode" not in file_scan_columns:
            connection.execute("ALTER TABLE file_scan_tasks ADD COLUMN analysis_mode TEXT NOT NULL DEFAULT 'static'")
        surface_columns = {row[1] for row in connection.execute("PRAGMA table_info(surface_tasks)")}
        if "target_type" not in surface_columns:
            connection.execute("ALTER TABLE surface_tasks ADD COLUMN target_type TEXT NOT NULL DEFAULT 'domain'")
        if "client_name" not in surface_columns:
            connection.execute("ALTER TABLE surface_tasks ADD COLUMN client_name TEXT NOT NULL DEFAULT 'Unassigned'")
        if "progress" not in surface_columns:
            connection.execute("ALTER TABLE surface_tasks ADD COLUMN progress INTEGER NOT NULL DEFAULT 0")
        if "progress_items" not in surface_columns:
            connection.execute("ALTER TABLE surface_tasks ADD COLUMN progress_items TEXT NOT NULL DEFAULT '[]'")
        legacy_reputation_table = "url" + "_scan_tasks"
        legacy_exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (legacy_reputation_table,)).fetchone()
        if legacy_exists:
            connection.execute(f"""INSERT OR IGNORE INTO reputation_tasks
                (id, user_id, target, engine, status, result, error, created_at, completed_at)
                SELECT id, user_id, target, engine, status, result, error, created_at, completed_at
                FROM {legacy_reputation_table}""")
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        if "is_admin" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "must_change_password" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1")
        if "totp_secret" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        if "totp_pending_secret" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN totp_pending_secret TEXT")
        if "totp_enabled" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
        if "user_uuid" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN user_uuid TEXT")
            for row in connection.execute("SELECT id FROM users WHERE user_uuid IS NULL"):
                connection.execute("UPDATE users SET user_uuid = ? WHERE id = ?", (str(uuid.uuid4()), row[0]))
        if "name" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT ''")
            connection.execute("UPDATE users SET name = username WHERE name = ''")
        backfill_local_intelligence(connection)
        init_workspace(connection)
        recovered = recover_interrupted_tasks(connection)
        if recovered:
            app.logger.warning("Marked %d task(s) interrupted by the previous shutdown as failed.", recovered)
        admin = connection.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            connection.execute(
                "INSERT INTO users (user_uuid, name, username, password_hash, is_admin, must_change_password, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), "Administrator", "admin", generate_password_hash("arasaka", method="pbkdf2:sha256:600000"), 1, 1, datetime.now(timezone.utc).isoformat()),
            )
    harden_upload_dir(UPLOAD_DIR)
    start_upload_retention(DATABASE, UPLOAD_DIR, SERVICE_SETTINGS["UPLOAD_RETENTION_DAYS"])
    start_surface_scheduler(DATABASE)


def current_user():
    if not session.get("user_id"):
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.context_processor
def inject_current_user():
    return {"current_user": current_user, "csrf_token": csrf_token}


def csp_nonce():
    return g.get("csp_nonce", "")


def url_with(**changes):
    """URL of the current page with some query parameters replaced (None removes one)."""
    args = request.args.to_dict()
    for key, value in changes.items():
        if value is None:
            args.pop(key, None)
        else:
            args[key] = value
    return url_for(request.endpoint, **(request.view_args or {}), **args)


app.jinja_env.globals.update(
    csp_nonce=csp_nonce, url_with=url_with, navigation=navigation, rerun_args=rerun_args,
    modules=MODULES, module_icons=ICONS, admin_items=ADMIN_ITEMS,
)


@app.before_request
def prepare_security_context():
    g.csp_nonce = secrets.token_urlsafe(16)


def csrf_token():
                                                                           
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


@app.before_request
def protect_against_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    expected = session.get(CSRF_SESSION_KEY)
    provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not provided or not secrets.compare_digest(expected, provided):
        return render_template("csrf_error.html"), 400
    if app.config["WTF_CSRF_SSL_STRICT"] and request.is_secure:
        referrer = urlparse(request.referrer or "")
        if referrer.scheme != "https" or referrer.netloc != request.host:
            return render_template("csrf_error.html"), 400
    return None


@app.after_request
def apply_security_headers(response):
    nonce = g.get("csp_nonce") or secrets.token_urlsafe(16)
    policy = "; ".join((
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data: https://*.basemaps.cartocdn.com",
        "connect-src 'self'",
        "media-src 'self'",
        "worker-src 'self'",
        "manifest-src 'self'",
    ))
    response.headers.setdefault("Content-Security-Policy", policy)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("Origin-Agent-Cluster", "?1")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if response.mimetype in {"text/html", "application/json"}:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Sign in to access the workspace.", "warning")
            return redirect(url_for("login"))
        if user["must_change_password"] and request.endpoint != "change_password":
            flash("Change the temporary password before accessing the workspace.", "warning")
            return redirect(url_for("change_password"))
        return view(*args, **kwargs)
    return wrapped


def login_client_ip():
    try:
        peer_address = ipaddress.ip_address((request.remote_addr or "").strip())
    except ValueError:
        return "unavailable"
    if peer_address in LOOPBACK_PROXY_IPS:
        forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")
        try:
            return str(ipaddress.ip_address(forwarded_for[-1].strip()))
        except ValueError:
            pass
        try:
            return str(ipaddress.ip_address(request.headers.get("X-Real-IP", "").strip()))
        except ValueError:
            pass
    return str(peer_address)


def login_quarantine_remaining(connection, ip_address, now=None):
    now = now or datetime.now(timezone.utc)
    row = connection.execute("SELECT locked_until FROM login_ip_protection WHERE ip_address = ?", (ip_address,)).fetchone()
    if not row or not row["locked_until"]:
        return None
    try:
        locked_until = datetime.fromisoformat(row["locked_until"])
        locked_until = locked_until if locked_until.tzinfo else locked_until.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return locked_until - now if locked_until > now else None


def record_login_failure(connection, ip_address, now=None):
    now = now or datetime.now(timezone.utc)
    row = connection.execute("SELECT failed_attempts, lockout_level, last_failed_at FROM login_ip_protection WHERE ip_address = ?", (ip_address,)).fetchone()
    failed_attempts, lockout_level = 0, 0
    if row:
        try:
            last_failed = datetime.fromisoformat(row["last_failed_at"])
            last_failed = last_failed if last_failed.tzinfo else last_failed.replace(tzinfo=timezone.utc)
            if now - last_failed <= LOGIN_FAILURE_WINDOW:
                failed_attempts = int(row["failed_attempts"])
        except (TypeError, ValueError):
            pass
        lockout_level = int(row["lockout_level"])
    failed_attempts += 1
    locked_until = None
    if failed_attempts >= LOGIN_FAILURE_LIMIT:
        lockout_level += 1
        quarantine = INITIAL_IP_QUARANTINE + QUARANTINE_INCREMENT * (lockout_level - 1)
        locked_until = (now + quarantine).isoformat()
        failed_attempts = 0
    connection.execute(
        """INSERT INTO login_ip_protection (ip_address, failed_attempts, lockout_level, locked_until, last_failed_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET failed_attempts = excluded.failed_attempts,
            lockout_level = excluded.lockout_level, locked_until = excluded.locked_until,
            last_failed_at = excluded.last_failed_at""",
        (ip_address, failed_attempts, lockout_level, locked_until, now.isoformat()),
    )
    connection.commit()
    return quarantine if locked_until else None


def clear_login_failures(connection, ip_address):
    connection.execute("DELETE FROM login_ip_protection WHERE ip_address = ?", (ip_address,))
    connection.commit()


def admin_required(view):
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user()["is_admin"]:
            flash("This action requires an administrator account.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        ip_address = login_client_ip()
        remaining = login_quarantine_remaining(db(), ip_address)
        if remaining:
            minutes = max(1, int((remaining.total_seconds() + 59) // 60))
            return render_template("login.html", login_error=f"Too many failed sign-in attempts. This IP is quarantined for about {minutes} more minute{'s' if minutes != 1 else ''}."), 429
        user = db().execute("SELECT * FROM users WHERE username = ?", (request.form.get("username", "").strip().lower(),)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            clear_login_failures(db(), ip_address)
            session.clear(); session.permanent = True
            if user["totp_enabled"]:
                session["pending_2fa_user_id"] = user["id"]
                return redirect(url_for("two_factor_login"))
            session["user_id"] = user["id"]
            return redirect(url_for("change_password") if user["must_change_password"] else url_for("dashboard"))
        quarantine = record_login_failure(db(), ip_address)
        if quarantine:
            minutes = int(quarantine.total_seconds() // 60)
            return render_template("login.html", login_error=f"Too many failed sign-in attempts. This IP is quarantined for {minutes} minutes."), 429
        return render_template("login.html", login_error="Invalid credentials."), 401
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/two-factor", methods=["GET", "POST"])
def two_factor_login():
    pending_user_id = session.get("pending_2fa_user_id")
    if not pending_user_id:
        return redirect(url_for("login"))
    user = db().execute("SELECT * FROM users WHERE id = ?", (pending_user_id,)).fetchone()
    if not user or not user["totp_enabled"]:
        session.clear()
        flash("Two-factor authentication is no longer available for this account.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        secret = decrypt_secret(user["totp_secret"], BASE_DIR)
        if secret and valid_code(secret, request.form.get("code")):
            clear_login_failures(db(), login_client_ip())
            session.clear(); session.permanent = True; session["user_id"] = user["id"]
            return redirect(url_for("change_password") if user["must_change_password"] else url_for("dashboard"))
        quarantine = record_login_failure(db(), login_client_ip())
        if quarantine:
            minutes = int(quarantine.total_seconds() // 60)
            return render_template("two_factor.html", login_error=f"Too many failed sign-in attempts. This IP is quarantined for {minutes} minutes."), 429
        return render_template("two_factor.html", login_error="Invalid authentication code."), 401
    return render_template("two_factor.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        if not check_password_hash(current_user()["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
        elif len(password) < 10:
            flash("Password must be at least 10 characters.", "error")
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        else:
            db().execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                (generate_password_hash(password, method="pbkdf2:sha256:600000"), current_user()["id"]))
            db().commit()
            flash("Password updated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html")


@app.route("/two-factor-settings", methods=["GET", "POST"])
@login_required
def two_factor_settings():
    user = current_user()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "begin":
            pending = create_secret()
            db().execute("UPDATE users SET totp_pending_secret = ? WHERE id = ?", (encrypt_secret(pending, BASE_DIR), user["id"]))
            db().commit()
            return redirect(url_for("two_factor_settings"))
        if action == "confirm":
            pending = decrypt_secret(user["totp_pending_secret"], BASE_DIR)
            if pending and valid_code(pending, request.form.get("code")):
                db().execute("UPDATE users SET totp_secret = ?, totp_pending_secret = NULL, totp_enabled = 1 WHERE id = ?", (encrypt_secret(pending, BASE_DIR), user["id"]))
                db().commit()
                flash("Two-factor authentication is enabled.", "success")
                return redirect(url_for("two_factor_settings"))
            flash("Enter a valid six-digit code from your authenticator app.", "error")
        if action == "disable":
            if not check_password_hash(user["password_hash"], request.form.get("current_password", "")):
                flash("Current password is incorrect.", "error")
            else:
                db().execute("UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, totp_enabled = 0 WHERE id = ?", (user["id"],))
                db().commit()
                flash("Two-factor authentication is disabled.", "success")
                return redirect(url_for("two_factor_settings"))
    user = current_user()
    pending = decrypt_secret(user["totp_pending_secret"], BASE_DIR) if user["totp_pending_secret"] else None
    return render_template("two_factor_settings.html", pending_qr=qr_data_uri(provisioning_uri(pending, user["username"])) if pending else None)


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "analyst")
        if role not in {"analyst", "admin"}:
            flash("Invalid role selected.", "error")
        elif len(name) < 2 or len(username) < 3 or len(password) < 10:
            flash("Name must be at least 2 characters, username 3, and temporary password 10.", "error")
        else:
            try:
                db().execute(
                    "INSERT INTO users (user_uuid, name, username, password_hash, is_admin, must_change_password, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (str(uuid.uuid4()), name, username, generate_password_hash(password, method="pbkdf2:sha256:600000"), 1 if role == "admin" else 0, datetime.now(timezone.utc).isoformat()),
                )
                db().commit()
                flash("Account created. The user must change their password when they sign in.", "success")
                return redirect(url_for("manage_users"))
            except sqlite3.IntegrityError:
                flash("That username already exists.", "error")
    users = db().execute("SELECT user_uuid, name, username, is_admin, must_change_password, created_at FROM users ORDER BY is_admin DESC, name").fetchall()
    return render_template("users.html", users=users)


@app.route("/admin/source-apis", methods=["GET", "POST"])
@admin_required
def source_apis():
    if request.method == "POST":
        settings = save_source_api_settings({
            "virustotal_api_key": request.form.get("virustotal_api_key", ""),
            "kaspersky_otip_api_key": request.form.get("kaspersky_otip_api_key", ""),
            "phishtank_api_key": request.form.get("phishtank_api_key", ""),
            "urlhaus_api_key": request.form.get("urlhaus_api_key", ""),
            "malwarebazaar_api_key": request.form.get("malwarebazaar_api_key", ""),
            "otx_api_key": request.form.get("otx_api_key", ""),
            "abuseipdb_api_key": request.form.get("abuseipdb_api_key", ""),
            "shodan_api_key": request.form.get("shodan_api_key", ""),
            "hybrid_analysis_api_key": request.form.get("hybrid_analysis_api_key", ""),
            "filescan_api_key": request.form.get("filescan_api_key", ""),
            "ai_provider": request.form.get("ai_provider", "openai"),
            "ai_api_key": request.form.get("ai_api_key", ""),
            "ai_model": request.form.get("ai_model", ""),
        })
        flash("Source API settings saved to config.ini.", "success")
        return redirect(url_for("source_apis"))
    settings = source_api_settings()
    configured = {key: bool(value) for key, value in settings.items()}
    return render_template("source_apis.html", settings=settings, configured=configured)


@app.post("/admin/users/<username>/reset-password")
@admin_required
def reset_user_password(username):
    password = request.form.get("password", "")
    user = db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        flash("User not found.", "error")
    elif len(password) < 10:
        flash("Temporary password must be at least 10 characters.", "error")
    else:
        db().execute("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
            (generate_password_hash(password, method="pbkdf2:sha256:600000"), user["id"]))
        db().commit()
        flash(f"Password reset for {username}. They must change it when signing in.", "success")
    return redirect(url_for("manage_users"))


@app.post("/admin/users/<username>/role")
@admin_required
def update_user_role(username):
    role = request.form.get("role", "")
    user = db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        flash("User not found.", "error")
    elif user["id"] == current_user()["id"]:
        flash("You cannot change your own administrator role.", "error")
    elif role not in {"analyst", "admin"}:
        flash("Invalid role selected.", "error")
    else:
        db().execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if role == "admin" else 0, user["id"]))
        db().commit()
        flash(f"Role updated for {username}.", "success")
    return redirect(url_for("manage_users"))


@app.post("/admin/users/<username>/delete")
@admin_required
def delete_user(username):
    user = db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        flash("User not found.", "error")
    elif user["id"] == current_user()["id"]:
        flash("You cannot delete your own administrator account.", "error")
    else:
        db().execute("DELETE FROM users WHERE id = ?", (user["id"],))
        db().commit()
        flash(f"User {username} deleted.", "success")
    return redirect(url_for("manage_users"))


register_dns_routes(app, DATABASE, db, current_user, login_required)
register_whois_routes(app, DATABASE, db, current_user, login_required)
register_blacklist_routes(app, DATABASE, db, current_user, login_required)
register_spf_routes(app, DATABASE, db, current_user, login_required)
register_reputation_routes(app, DATABASE, db, current_user, login_required)
register_surface_routes(app, DATABASE, db, current_user, login_required)
register_email_exposure_routes(app, DATABASE, db, current_user, login_required)
register_live_url_routes(app, DATABASE, db, current_user, login_required, BASE_DIR / "instance" / "live_url_captures")
register_eml_routes(app, DATABASE, db, current_user, login_required, UPLOAD_DIR)
register_file_scan_routes(app, DATABASE, db, current_user, login_required, UPLOAD_DIR)
register_workspace_routes(app, db, current_user, login_required)


@app.errorhandler(413)
def too_large(_error):
    limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    flash(f"File too large. The maximum upload size is {limit_mb} MB.", "error")
    referrer = urlparse(request.referrer or "")
    same_origin = referrer.netloc == request.host and referrer.path.startswith("/")
    return redirect(referrer.path if same_origin else url_for("dashboard"))


def main():
    init_db()
    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"},
        host=SERVICE_SETTINGS["INTERFACE"],
        port=SERVICE_SETTINGS["PORT"],
    )


if __name__ == "__main__":
    main()
