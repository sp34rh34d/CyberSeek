"""Storage hygiene for uploaded samples (emails and files under analysis)."""
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

SAMPLE_TABLES = ("eml_tasks", "file_scan_tasks")
RETENTION_SWEEP_SECONDS = 6 * 60 * 60
logger = logging.getLogger(__name__)


def protect_upload(path):
    """Never leave a stored sample executable; match the installer's 640 file policy."""
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def harden_upload_dir(upload_dir):
    upload_dir = Path(upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(upload_dir, 0o750)
    except OSError:
        pass
    for path in upload_dir.iterdir():
        if path.is_file() and path.name != ".gitkeep":
            protect_upload(path)


def purge_expired_samples(database, upload_dir, retention_days, now=None):
    """Delete stored samples of finished tasks older than the retention window.

    Task reports stay in the database; only the original email or file is removed, so
    attachment downloads and re-parsing are no longer available for those tasks.
    """
    if retention_days <= 0:
        return 0
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=retention_days)).isoformat()
    upload_root = Path(upload_dir).resolve()
    removed = 0
    with sqlite3.connect(database) as connection:
        for table in SAMPLE_TABLES:
            rows = connection.execute(
                f"""SELECT stored_path FROM {table}
                    WHERE status NOT IN ('Running', 'Queued') AND COALESCE(completed_at, created_at) < ?""",
                (cutoff,),
            ).fetchall()
            for (stored_path,) in rows:
                path = Path(stored_path or "")
                try:
                    resolved = path.resolve()
                except OSError:
                    continue
                if upload_root in resolved.parents and resolved.is_file():
                    resolved.unlink(missing_ok=True)
                    removed += 1
    return removed


def start_upload_retention(database, upload_dir, retention_days):
    if retention_days <= 0:
        return None

    def sweep():
        while True:
            try:
                removed = purge_expired_samples(database, upload_dir, retention_days)
                if removed:
                    logger.info("Removed %d stored sample(s) older than %d days.", removed, retention_days)
            except (OSError, sqlite3.Error) as exc:
                logger.warning("Sample retention sweep failed: %s", exc)
            time.sleep(RETENTION_SWEEP_SECONDS)

    thread = threading.Thread(target=sweep, name="cyberseek-upload-retention", daemon=True)
    thread.start()
    return thread
