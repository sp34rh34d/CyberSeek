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
)


def add_task_visibility_columns(connection):
                                                                       
    for table in TASK_TABLES:
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if "is_private" not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0")


def is_private_task(form):
    return 1 if form.get("is_private") == "1" else 0


def visible_tasks(connection, table, user_id, limit=100):
    return connection.execute(
        f"""SELECT task.*, users.name AS owner_name
            FROM {table} AS task
            JOIN users ON users.id = task.user_id
            WHERE task.is_private = 0 OR task.user_id = ?
            ORDER BY task.created_at DESC
            LIMIT ?""",
        (user_id, limit),
    ).fetchall()


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
