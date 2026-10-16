import math
import re
from datetime import datetime, timezone

TASK_TABLES = (
    "dns_tasks",
    "whois_tasks",
    "blacklist_tasks",
    "spf_tasks",
    "reputation_tasks",
    "live_url_tasks",
    "eml_tasks",
    "file_scan_tasks",
    "surface_tasks",
    "email_exposure_tasks",
)
HISTORY_PAGE_SIZE = 24
HISTORY_STATUSES = ("Running", "Queued", "Complete", "Failed", "Paused")
# Surface monitors are rescheduled by their own scheduler, so they are never marked interrupted.
INTERRUPTIBLE_TABLES = tuple(table for table in TASK_TABLES if table != "surface_tasks")
INTERRUPTED_ERROR = "Interrupted: the service restarted before this task finished. Run it again to retry."


def add_task_visibility_columns(connection):
    for table in TASK_TABLES:
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if "is_private" not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0")
        connection.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_created ON {table}(created_at)")
        connection.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_owner ON {table}(user_id, is_private)")
        connection.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_status ON {table}(status)")


def recover_interrupted_tasks(connection):
    """Fail tasks whose worker thread died with the previous process.

    Tasks that already stored a partial result (a file scan waiting on a dynamic sandbox)
    are left alone: their detail view resumes polling the provider.
    """
    recovered = 0
    now = datetime.now(timezone.utc).isoformat()
    for table in INTERRUPTIBLE_TABLES:
        recovered += connection.execute(
            f"""UPDATE {table} SET status = 'Failed', error = ?, completed_at = ?
                WHERE status IN ('Running', 'Queued') AND result IS NULL""",
            (INTERRUPTED_ERROR, now),
        ).rowcount
    return recovered


def is_private_task(form):
    return 1 if form.get("is_private") == "1" else 0


def _history_filters(args):
    status = args.get("status", "")
    date = args.get("date", "")
    try:
        page = max(1, int(args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    return {
        "q": args.get("q", "").strip()[:200],
        "status": status if status in HISTORY_STATUSES else "",
        "owner": "mine" if args.get("owner") == "mine" else "",
        "date": date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) else "",
        "page": page,
    }


def task_history(connection, table, user_id, args, search_columns, page_size=HISTORY_PAGE_SIZE):
    """One page of visible tasks plus status totals, filtered by the request query string."""
    filters = _history_filters(args)
    visible = "(task.is_private = 0 OR task.user_id = ?)"
    where, params = [visible], [user_id]
    if filters["q"]:
        pattern = "%" + filters["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        columns = [f"task.{column}" for column in search_columns] + ["users.name"]
        where.append("(" + " OR ".join(f"COALESCE({column}, '') LIKE ? ESCAPE '\\'" for column in columns) + ")")
        params += [pattern] * len(columns)
    if filters["owner"]:
        where.append("task.user_id = ?")
        params.append(user_id)
    if filters["date"]:
        where.append("substr(task.created_at, 1, 10) = ?")
        params.append(filters["date"])
    base = f"FROM {table} AS task JOIN users ON users.id = task.user_id WHERE " + " AND ".join(where)
    counts = {row[0]: row[1] for row in connection.execute(f"SELECT task.status, COUNT(*) {base} GROUP BY task.status", params)}
    stats = {
        "total": sum(counts.values()),
        "active": counts.get("Running", 0) + counts.get("Queued", 0),
        "complete": counts.get("Complete", 0),
        "failed": counts.get("Failed", 0) + counts.get("Error", 0),
    }
    if filters["status"] == "Failed":
        status_clause, status_params = " AND task.status IN ('Failed', 'Error')", []
    elif filters["status"]:
        status_clause, status_params = " AND task.status = ?", [filters["status"]]
    else:
        status_clause, status_params = "", []
    matching = sum(counts.values()) if not filters["status"] else (
        stats["failed"] if filters["status"] == "Failed" else counts.get(filters["status"], 0))
    pages = max(1, math.ceil(matching / page_size))
    page = min(filters["page"], pages)
    items = connection.execute(
        f"SELECT task.*, users.name AS owner_name {base}{status_clause} ORDER BY task.created_at DESC LIMIT ? OFFSET ?",
        params + status_params + [page_size, (page - 1) * page_size],
    ).fetchall()
    filters["page"] = page
    return {
        "items": items, "stats": stats, "filters": filters, "page": page, "pages": pages,
        "matching": matching, "filtered": any(filters[key] for key in ("q", "status", "owner", "date")),
    }


def visible_task(connection, table, task_id, user_id):
    return connection.execute(
        f"""SELECT task.*, users.name AS owner_name
            FROM {table} AS task
            JOIN users ON users.id = task.user_id
            WHERE task.id = ? AND (task.is_private = 0 OR task.user_id = ?)""",
        (task_id, user_id),
    ).fetchone()


def delete_owned_task(connection, table, task_id, user_id):
    return connection.execute(
        f"DELETE FROM {table} WHERE id = ? AND user_id = ?", (task_id, user_id)
    )


def module_history(connection, key, user_id, args):
    from utils.modules import MODULES
    module = MODULES[key]
    return task_history(connection, module["table"], user_id, args, module["search"])
