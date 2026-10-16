"""Cross-module workspace: overview dashboard, global search, live task status, analyst notes, and pivots."""
import re
from datetime import datetime, timedelta, timezone

from flask import abort, flash, jsonify, redirect, render_template, request, url_for

from utils.local_heuristics import _indicator
from utils.modules import IOC_SOURCE_MODULES, MODULES, VIEW_ENDPOINTS
from utils.source_config import source_api_settings

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
NOTE_MAX_LENGTH = 4000
SEARCH_LIMIT = 8


def init_workspace(connection):
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS task_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module TEXT NOT NULL,
            task_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_task_notes_task ON task_notes(module, task_id);
        CREATE INDEX IF NOT EXISTS idx_local_ioc_task ON local_ioc_observations(task_id);
    """)
    # Remove notes and IoC observations left behind by tasks deleted in earlier versions.
    for key, module in MODULES.items():
        connection.execute(f"DELETE FROM task_notes WHERE module = ? AND task_id NOT IN (SELECT id FROM {module['table']})", (key,))
    known = " UNION ".join(f"SELECT id FROM {MODULES[key]['table']}" for key in IOC_SOURCE_MODULES)
    connection.execute(f"DELETE FROM local_ioc_observations WHERE task_id NOT IN ({known})")


def _visible_clause(alias="task"):
    return f"({alias}.is_private = 0 OR {alias}.user_id = ?)"


def _visible_ioc_tasks():
    """SQL selecting (task_id, module) for IoC-producing tasks visible to one user (one param per module)."""
    return " UNION ALL ".join(
        f"SELECT id AS task_id, '{key}' AS module FROM {MODULES[key]['table']} AS task WHERE {_visible_clause()}"
        for key in IOC_SOURCE_MODULES
    )


def classify_indicator(value):
    value = (value or "").strip()
    if EMAIL_RE.fullmatch(value):
        return ("Email", value.lower())
    return _indicator(value)


def pivots(kind, value):
    """Module forms that accept this indicator, pre-filled."""
    if kind == "Email":
        return [("Email exposure", url_for("email_exposure", email=value))]
    options = [("Reputation", url_for("reputation_lookup", target=value))]
    if kind in ("IP address", "Domain"):
        options += [
            ("WHOIS", url_for("whois_lookup", target=value)),
            ("DNS", url_for("dns_queries", domain=value, record_type="PTR" if kind == "IP address" else "A")),
            ("Blacklist", url_for("blacklist_check", target=value)),
        ]
    if kind == "Domain":
        options.append(("SPF", url_for("spf_check", domain=value)))
    if kind == "URL":
        options.append(("Live URL", url_for("live_url_analysis", target=value)))
    return options


def task_indicators(connection, task_id, limit=40):
    rows = connection.execute(
        """SELECT indicator_type, indicator_value,
                  SUM(verdict = 'Malicious') AS malicious, SUM(verdict = 'Suspicious') AS suspicious,
                  GROUP_CONCAT(DISTINCT source) AS sources
           FROM local_ioc_observations WHERE task_id = ?
           GROUP BY indicator_type, indicator_value
           ORDER BY malicious DESC, suspicious DESC, indicator_value LIMIT ?""",
        (task_id, limit),
    ).fetchall()
    return [{**dict(row), "verdict": _verdict(row), "pivots": pivots(row["indicator_type"], row["indicator_value"])} for row in rows]


def _verdict(row):
    return "Malicious" if row["malicious"] else "Suspicious" if row["suspicious"] else "Observed"


def module_overview(connection, user_id):
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    cards = []
    for key, module in MODULES.items():
        row = connection.execute(
            f"""SELECT COUNT(*) AS total,
                       SUM(status IN ('Running', 'Queued')) AS active,
                       SUM(status IN ('Failed', 'Error') AND created_at >= ?) AS failed_week,
                       SUM(created_at >= ?) AS week,
                       MAX(created_at) AS last_at
                FROM {module['table']} AS task WHERE {_visible_clause()}""",
            (since, since, user_id),
        ).fetchone()
        cards.append({"key": key, "label": module["label"], "group": module["group"], "endpoint": module["list"],
                      "total": row["total"] or 0, "active": row["active"] or 0, "week": row["week"] or 0,
                      "failed_week": row["failed_week"] or 0, "last_at": row["last_at"]})
    return cards


def recent_tasks(connection, user_id, limit=12):
    parts, params = [], []
    for key, module in MODULES.items():
        parts.append(
            f"""SELECT '{key}' AS module, task.id, task.{module['title']} AS title, task.status, task.created_at,
                       task.user_id, users.name AS owner_name
                FROM {module['table']} AS task JOIN users ON users.id = task.user_id WHERE {_visible_clause()}"""
        )
        params.append(user_id)
    return connection.execute("SELECT * FROM (" + " UNION ALL ".join(parts) + ") ORDER BY created_at DESC LIMIT ?", params + [limit]).fetchall()


def flagged_indicators(connection, user_id, limit=10):
    params = [user_id] * len(IOC_SOURCE_MODULES)
    rows = connection.execute(
        f"""SELECT obs.indicator_type, obs.indicator_value, MAX(obs.observed_at) AS last_seen,
                   SUM(obs.verdict = 'Malicious') AS malicious, SUM(obs.verdict = 'Suspicious') AS suspicious,
                   COUNT(DISTINCT obs.task_id) AS tasks
            FROM local_ioc_observations AS obs
            JOIN ({_visible_ioc_tasks()}) AS visible ON visible.task_id = obs.task_id
            GROUP BY obs.indicator_type, obs.indicator_value
            HAVING malicious > 0 OR suspicious > 0
            ORDER BY last_seen DESC LIMIT ?""",
        params + [limit],
    ).fetchall()
    return [{**dict(row), "verdict": _verdict(row)} for row in rows]


def search_tasks(connection, user_id, query):
    pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    groups = []
    for key, module in MODULES.items():
        columns = [f"COALESCE(task.{column}, '') LIKE ? ESCAPE '\\'" for column in module["search"]]
        where = f"{_visible_clause()} AND ({' OR '.join(columns)})"
        params = [user_id] + [pattern] * len(columns)
        total = connection.execute(f"SELECT COUNT(*) FROM {module['table']} AS task WHERE {where}", params).fetchone()[0]
        if not total:
            continue
        rows = connection.execute(
            f"""SELECT task.*, users.name AS owner_name FROM {module['table']} AS task
                JOIN users ON users.id = task.user_id WHERE {where}
                ORDER BY task.created_at DESC LIMIT ?""",
            params + [SEARCH_LIMIT],
        ).fetchall()
        groups.append({"key": key, "label": module["label"], "title": module["title"], "total": total, "rows": rows,
                       "more_url": url_for(module["list"], q=query) + "#task-history"})
    return groups


def search_indicators(connection, user_id, query, limit=25):
    pattern = "%" + query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    params = [user_id] * len(IOC_SOURCE_MODULES) + [pattern, limit]
    rows = connection.execute(
        f"""SELECT obs.indicator_type, obs.indicator_value, MAX(obs.observed_at) AS last_seen,
                   SUM(obs.verdict = 'Malicious') AS malicious, SUM(obs.verdict = 'Suspicious') AS suspicious,
                   GROUP_CONCAT(DISTINCT visible.module || ':' || obs.task_id) AS task_refs
            FROM local_ioc_observations AS obs
            JOIN ({_visible_ioc_tasks()}) AS visible ON visible.task_id = obs.task_id
            WHERE lower(obs.indicator_value) LIKE ? ESCAPE '\\'
            GROUP BY obs.indicator_type, obs.indicator_value
            ORDER BY malicious DESC, suspicious DESC, last_seen DESC LIMIT ?""",
        params,
    ).fetchall()
    results = []
    for row in rows:
        refs = [ref.split(":", 1) for ref in (row["task_refs"] or "").split(",") if ":" in ref][:6]
        results.append({**dict(row), "verdict": _verdict(row), "pivots": pivots(row["indicator_type"], row["indicator_value"]),
                        "tasks": [{"label": MODULES[module]["label"], "url": url_for(MODULES[module]["view"], task_id=task_id)} for module, task_id in refs]})
    return results


def register_workspace_routes(app, db, current_user, login_required):
    def can_see(module, task_id):
        table = MODULES[module]["table"]
        return db().execute(f"SELECT 1 FROM {table} AS task WHERE id = ? AND {_visible_clause()}", (task_id, current_user()["id"])).fetchone()

    @app.context_processor
    def inject_task_workspace():
        """Expose notes, observed indicators, and live-status wiring to task report pages."""
        module = VIEW_ENDPOINTS.get(request.endpoint or "")
        task_id = (request.view_args or {}).get("task_id")
        if not module or not task_id or not current_user() or not can_see(module, task_id):
            return {}
        notes = db().execute(
            """SELECT task_notes.*, users.name AS author FROM task_notes JOIN users ON users.id = task_notes.user_id
               WHERE module = ? AND task_id = ? ORDER BY created_at""",
            (module, task_id),
        ).fetchall()
        return {
            "live_task": {"id": task_id, "status_url": url_for("task_status", module=module)},
            "task_notes": {"module": module, "task_id": task_id, "notes": notes,
                           "indicators": task_indicators(db(), task_id) if module in IOC_SOURCE_MODULES else []},
        }

    @app.get("/dashboard")
    @login_required
    def dashboard():
        user_id = current_user()["id"]
        settings = source_api_settings()
        api_keys = {key: bool(value) for key, value in settings.items() if key.endswith("_api_key") and key != "ai_api_key"}
        return render_template(
            "dashboard.html",
            cards=module_overview(db(), user_id),
            recent=recent_tasks(db(), user_id),
            flagged=flagged_indicators(db(), user_id),
            api_configured=sum(api_keys.values()), api_total=len(api_keys),
            ai_configured=bool(settings.get("ai_api_key")),
        )

    @app.get("/search")
    @login_required
    def global_search():
        query = request.args.get("q", "").strip()[:300]
        if not query:
            return render_template("search.html", query="", indicator=None, task_groups=[], indicators=[])
        user_id = current_user()["id"]
        classified = classify_indicator(query)
        indicator = {"type": classified[0], "value": classified[1], "pivots": pivots(*classified)} if classified else None
        return render_template(
            "search.html", query=query, indicator=indicator,
            task_groups=search_tasks(db(), user_id, query),
            indicators=search_indicators(db(), user_id, query.lower() if not classified else classified[1]),
        )

    @app.get("/api/tasks/<module>/status")
    @login_required
    def task_status(module):
        if module not in MODULES:
            abort(404)
        ids = [value for value in request.args.get("ids", "").split(",") if value][:100]
        if not ids:
            return jsonify({"tasks": {}})
        table = MODULES[module]["table"]
        placeholders = ",".join("?" for _ in ids)
        rows = db().execute(
            f"SELECT id, status FROM {table} AS task WHERE id IN ({placeholders}) AND {_visible_clause()}",
            ids + [current_user()["id"]],
        ).fetchall()
        return jsonify({"tasks": {row["id"]: row["status"] for row in rows}})

    @app.post("/tasks/<module>/<task_id>/notes")
    @login_required
    def add_task_note(module, task_id):
        if module not in MODULES or not can_see(module, task_id):
            abort(404)
        body = request.form.get("body", "").strip()
        if not body:
            flash("Write a note before saving.", "error")
        elif len(body) > NOTE_MAX_LENGTH:
            flash(f"Notes are limited to {NOTE_MAX_LENGTH} characters.", "error")
        else:
            db().execute("INSERT INTO task_notes (module, task_id, user_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
                         (module, task_id, current_user()["id"], body, datetime.now(timezone.utc).isoformat()))
            db().commit()
            flash("Note added.", "success")
        return redirect(url_for(MODULES[module]["view"], task_id=task_id) + "#analyst-notes")

    @app.post("/tasks/<module>/<task_id>/notes/<int:note_id>/delete")
    @login_required
    def delete_task_note(module, task_id, note_id):
        if module not in MODULES or not can_see(module, task_id):
            abort(404)
        deleted = db().execute("DELETE FROM task_notes WHERE id = ? AND module = ? AND task_id = ? AND user_id = ?",
                               (note_id, module, task_id, current_user()["id"])).rowcount
        db().commit()
        flash("Note deleted." if deleted else "Only the author can delete a note.", "success" if deleted else "error")
        return redirect(url_for(MODULES[module]["view"], task_id=task_id) + "#analyst-notes")
