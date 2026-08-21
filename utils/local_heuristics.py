                                                                           

                                                                             
                                                                           
                                                                             
   

import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", re.IGNORECASE)
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
VERDICTS = {"malicious": "Malicious", "listed": "Malicious", "suspicious": "Suspicious", "clean": "Clean"}


def init_local_heuristics(connection):
                                                                            
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS local_ioc_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            source TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            verdict TEXT NOT NULL DEFAULT 'Unknown',
            detail TEXT,
            observed_at TEXT NOT NULL,
            UNIQUE(task_id, source, indicator_type, indicator_value)
        );
        CREATE INDEX IF NOT EXISTS idx_local_ioc_value
            ON local_ioc_observations(indicator_type, indicator_value);
        CREATE TABLE IF NOT EXISTS local_indicators (
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            observation_count INTEGER NOT NULL DEFAULT 0,
            malicious_count INTEGER NOT NULL DEFAULT 0,
            suspicious_count INTEGER NOT NULL DEFAULT 0,
            clean_count INTEGER NOT NULL DEFAULT 0,
            unknown_count INTEGER NOT NULL DEFAULT 0,
            sources TEXT NOT NULL DEFAULT '[]',
            PRIMARY KEY(indicator_type, indicator_value)
        );
    """)


def _verdict(value):
    return VERDICTS.get(str(value or "").strip().lower(), "Unknown")


def _indicator(value, hinted_type=None):
                                                                      
    value = str(value or "").strip().rstrip(".")
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
        return ("IP address", str(address)) if address.is_global else None
    except ValueError:
        pass
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        try:
            if not ipaddress.ip_address(parsed.hostname).is_global:
                return None
        except ValueError:
            if not DOMAIN_RE.fullmatch(parsed.hostname):
                return None
        return ("URL", value)
    lowered = value.lower()
    if len(lowered) in HASH_LENGTHS and re.fullmatch(r"[a-f0-9]+", lowered):
        return (HASH_LENGTHS[len(lowered)].upper(), lowered)
    if DOMAIN_RE.fullmatch(lowered):
        return ("Domain", lowered)
    return None


def _observation(target, source, verdict="Unknown", detail=None, hinted_type=None):
    indicator = _indicator(target, hinted_type)
    if not indicator:
        return None
    return {
        "source": str(source or "Local collection")[:120],
        "indicator_type": indicator[0],
        "indicator_value": indicator[1],
        "verdict": _verdict(verdict),
        "detail": json.dumps(detail, ensure_ascii=False, separators=(",", ":"))[:2000] if detail else None,
    }


def _reputation_observations(report):
    rows = []
    target = report.get("target")
    for result in report.get("results", []):
        if isinstance(result, dict):
            row = _observation(target, f"Reputation · {result.get('engine', 'source')}", result.get("verdict"), {"state": result.get("state")})
            if row:
                rows.append(row)
    associations = report.get("associations", {})
    for kind, values in associations.items():
        for item in values or []:
            if isinstance(item, dict):
                value = item.get("value") or item.get("sha256") or item.get("md5")
                verdict = item.get("reputation", "Unknown")
                detail = {"association": kind, "malicious": item.get("malicious"), "suspicious": item.get("suspicious")}
            else:
                value, verdict, detail = item, "Unknown", {"association": kind}
            row = _observation(value, "Reputation · associated intelligence", verdict, detail, kind)
            if row:
                rows.append(row)
    return rows


def _blacklist_observations(report):
    rows = []
    for check in report.get("checks", []):
        if not isinstance(check, dict):
            continue
        row = _observation(
            check.get("subject"), f"Blacklist · {check.get('provider', 'source')}", check.get("status"),
            {"answer": check.get("answers"), "kind": check.get("kind")}, check.get("kind"),
        )
        if row:
            rows.append(row)
    return rows


def _file_observations(report):
    rows = []
    hash_verdict = (report.get("hash_reputation") or {}).get("verdict", "Unknown")
    for value in (report.get("hashes") or {}).values():
        row = _observation(value, "File scan · static hash", hash_verdict)
        if row:
            rows.append(row)
    for kind, values in (report.get("iocs") or {}).items():
        for value in values or []:
            row = _observation(value, "File scan · static artifact", "Unknown", {"artifact": kind}, kind)
            if row:
                rows.append(row)
    dynamic = report.get("dynamic") or {}
    for item in dynamic.get("network_requests", []):
        if isinstance(item, dict):
            row = _observation(item.get("value"), "File scan · dynamic sandbox", dynamic.get("verdict", "Unknown"), item, item.get("kind"))
            if row:
                rows.append(row)
    return rows


def _live_url_observations(report):
    rows = []
    verdict = (report.get("ai_verdict") or report.get("assessment") or {}).get("verdict", "Unknown")
    for value, source in ((report.get("target"), "Live URL · submitted target"), (report.get("final_url"), "Live URL · final target")):
        row = _observation(value, source, verdict)
        if row:
            rows.append(row)
    vt = report.get("virustotal") or {}
    network = report.get("network") or {}
    row = _observation(network.get("ip"), "Live URL · network information", vt.get("verdict", verdict), network)
    if row:
        rows.append(row)
    for item in report.get("resources", []):
        if isinstance(item, dict):
            row = _observation(item.get("url"), "Live URL · loaded resource", "Unknown", {"type": item.get("type"), "status": item.get("status")})
            if row:
                rows.append(row)
    return rows


def _observations(source_kind, report):
    if source_kind == "reputation":
        return _reputation_observations(report)
    if source_kind == "blacklist":
        return _blacklist_observations(report)
    if source_kind == "file_scan":
        return _file_observations(report)
    if source_kind == "live_url":
        return _live_url_observations(report)
    return []


def _rebuild_indicator_index(connection):
    connection.execute("DELETE FROM local_indicators")
    groups = connection.execute("""
        SELECT indicator_type, indicator_value, MIN(observed_at), MAX(observed_at), COUNT(*),
               SUM(verdict = 'Malicious'), SUM(verdict = 'Suspicious'),
               SUM(verdict = 'Clean'), SUM(verdict = 'Unknown')
        FROM local_ioc_observations
        GROUP BY indicator_type, indicator_value
    """).fetchall()
    for group in groups:
        indicator_type, value = group[0], group[1]
        sources = [row[0] for row in connection.execute(
            "SELECT DISTINCT source FROM local_ioc_observations WHERE indicator_type = ? AND indicator_value = ? ORDER BY source",
            (indicator_type, value),
        )]
        connection.execute("""
            INSERT INTO local_indicators
            (indicator_type, indicator_value, first_seen, last_seen, observation_count, malicious_count, suspicious_count, clean_count, unknown_count, sources)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (*group, json.dumps(sources, ensure_ascii=False)))


def _summary(connection, observations):
    keys = {(item["indicator_type"], item["indicator_value"]) for item in observations}
    matches = []
    for kind, value in keys:
        row = connection.execute("SELECT * FROM local_indicators WHERE indicator_type = ? AND indicator_value = ?", (kind, value)).fetchone()
        if row:
            matches.append(dict(row))
    malicious = sum(row["malicious_count"] for row in matches)
    suspicious = sum(row["suspicious_count"] for row in matches)
    clean = sum(row["clean_count"] for row in matches)
    verdict = "Malicious" if malicious else "Suspicious" if suspicious else "Clean" if clean else "Unknown"
    confidence = "High" if malicious >= 3 or suspicious >= 4 else "Medium" if malicious or suspicious else "Low"
    signals = []
    for row in sorted(matches, key=lambda item: (-item["malicious_count"], -item["suspicious_count"], item["indicator_value"]))[:6]:
        elevated = row["malicious_count"] + row["suspicious_count"]
        signals.append({"indicator": row["indicator_value"], "type": row["indicator_type"], "observations": row["observation_count"], "malicious": row["malicious_count"], "suspicious": row["suspicious_count"], "clean": row["clean_count"], "elevated": elevated})
    return {
        "source": "Local heuristic database", "tracked_indicators": len(matches), "observations": sum(row["observation_count"] for row in matches),
        "verdict": verdict, "confidence": confidence, "signals": signals,
    }


def ingest_local_intelligence(database, task_id, source_kind, report):
                                                                                 

                                                                            
                                                                
       
    observations = _observations(source_kind, report or {})
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        init_local_heuristics(connection)
        connection.execute("DELETE FROM local_ioc_observations WHERE task_id = ?", (task_id,))
        connection.executemany("""
            INSERT OR REPLACE INTO local_ioc_observations
            (task_id, source, indicator_type, indicator_value, verdict, detail, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [(task_id, row["source"], row["indicator_type"], row["indicator_value"], row["verdict"], row["detail"], now) for row in observations])
        _rebuild_indicator_index(connection)
        return _summary(connection, observations)


def backfill_local_intelligence(connection):
                                                                     

                                                                        
                                                                            
                                                                     
       
    init_local_heuristics(connection)
    sources = (
        ("blacklist_tasks", "blacklist"),
        ("reputation_tasks", "reputation"),
        ("file_scan_tasks", "file_scan"),
        ("live_url_tasks", "live_url"),
    )
    for table, source_kind in sources:
        for task_id, raw_report in connection.execute(f"SELECT id, result FROM {table} WHERE result IS NOT NULL"):
            try:
                report = json.loads(raw_report)
            except (TypeError, json.JSONDecodeError):
                continue
            observations = _observations(source_kind, report)
            connection.execute("DELETE FROM local_ioc_observations WHERE task_id = ?", (task_id,))
            now = datetime.now(timezone.utc).isoformat()
            connection.executemany("""
                INSERT OR REPLACE INTO local_ioc_observations
                (task_id, source, indicator_type, indicator_value, verdict, detail, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [(task_id, row["source"], row["indicator_type"], row["indicator_value"], row["verdict"], row["detail"], now) for row in observations])
    _rebuild_indicator_index(connection)
