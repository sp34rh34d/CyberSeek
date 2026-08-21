import json
import ipaddress
import re
import sqlite3
import threading
import time
import uuid
from base64 import urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from flask import flash, jsonify, make_response, redirect, render_template, request, url_for

from utils.analysis import analyze_url, is_private_host
from utils.local_heuristics import ingest_local_intelligence
from utils.dns import geolocate_result
from utils.source_config import source_api_settings
from utils.soc_summary import create_soc_summary
from utils.task_access import delete_owned_task, is_private_task, visible_task, visible_tasks


ENGINES = {
    "local": "Local heuristics",
    "virustotal": "VirusTotal",
    "kaspersky": "Kaspersky OpenTIP",
    "phishtank": "PhishTank",
    "talos": "Cisco Talos",
    "urlhaus": "URLhaus",
    "malwarebazaar": "MalwareBazaar",
    "otx": "AlienVault OTX",
    "abuseipdb": "AbuseIPDB",
}


def classify_target(value):
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return "url" if not is_private_host(parsed.hostname) else None
    try:
        return "ip" if ipaddress.ip_address(value).is_global else None
    except ValueError:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]{32}(?:[A-Fa-f0-9]{8}){0,4}", value):
        return "hash"
    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value) and not is_private_host(value):
        return "domain"
    return None


def _request_json(endpoint, method="GET", headers=None, body=None, timeout=12):
    request = Request(endpoint, data=body, headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", "replace")
            if not payload:
                return response.status, {}
            try:
                return response.status, json.loads(payload)
            except json.JSONDecodeError:
                return response.status, {"error": "Provider returned an unexpected non-JSON response."}
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(payload) if payload else {"error": f"HTTP {exc.code}"}
        except json.JSONDecodeError:
            if payload.lstrip().lower().startswith("<!doctype") or "challenges.cloudflare.com" in payload.lower():
                return exc.code, {"error": "Provider requires browser verification; the automated API lookup is unavailable."}
            return exc.code, {"error": "Provider returned an unexpected non-JSON error response."}
    except (URLError, TimeoutError, ValueError) as exc:
        return None, {"error": str(exc)}


def _result(engine, state, verdict, summary, reference=None, associations=None, engine_results=None, engine_summary=None):
    return {"engine": ENGINES[engine], "state": state, "verdict": verdict, "summary": summary, "reference": reference, "associations": associations or {"domains": [], "subdomains": [], "ips": [], "files": []}, "engine_results": engine_results or [], "engine_summary": engine_summary or {}}


def _vt_date(value):
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        return "Unavailable"


def _vt_dates(attributes):
    return {
        "first_seen": _vt_date(attributes.get("first_submission_date") or attributes.get("first_seen_date")),
        "last_seen": _vt_date(attributes.get("last_submission_date") or attributes.get("last_analysis_date") or attributes.get("last_modification_date")),
    }


def _vt_stats(attributes):
    stats = attributes.get("last_analysis_stats", {})
    malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
    reputation = "Malicious" if malicious else "Suspicious" if suspicious else "Clean" if stats else "Unknown"
    malicious_engines = sorted(
        engine for engine, finding in attributes.get("last_analysis_results", {}).items()
        if finding.get("category") == "malicious"
    )
    return {"reputation": reputation, "malicious": malicious, "suspicious": suspicious, "malicious_engines": malicious_engines}


def _vt_engine_results(attributes):
    raw_results = attributes.get("last_analysis_results") or attributes.get("results") or {}
    category_map = {"malicious": "Malicious", "suspicious": "Suspicious", "harmless": "Clean", "undetected": "Unknown"}
    results = []
    for source, finding in raw_results.items():
        category = str(finding.get("category", "unknown")).lower()
        results.append({
            "engine": finding.get("engine_name") or source,
            "verdict": category_map.get(category, "Unknown"),
            "detail": finding.get("result") or category.replace("-", " ").title(),
        })
    priority = {"Malicious": 0, "Suspicious": 1, "Clean": 2, "Unknown": 3}
    return sorted(results, key=lambda item: (priority.get(item["verdict"], 4), item["engine"].lower()))


def _vt_engine_summary(stats):
    return {
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "clean": int(stats.get("harmless", 0)),
        "unknown": sum(int(stats.get(key, 0)) for key in ("undetected", "timeout", "failure", "type-unsupported")),
    }


def _vt_associations(target, target_type, headers):
    resource = {"domain": f"domains/{quote(target, safe='')}", "ip": f"ip_addresses/{quote(target, safe='')}", "hash": f"files/{quote(target, safe='')}", "url": f"urls/{urlsafe_b64encode(target.encode()).decode().rstrip('=')}"}[target_type]
    relations = {
        "domain": ("resolutions", "subdomains", "communicating_files"),
        "ip": ("resolutions", "communicating_files"),
        "hash": ("contacted_domains", "contacted_ips", "communicating_files", "dropped_files"),
        "url": ("contacted_domains", "contacted_ips", "communicating_files"),
    }[target_type]
    associations = {"domains": {}, "subdomains": {}, "ips": {}, "files": {}}
    for relation in relations:
        status, payload = _request_json(
            f"https://www.virustotal.com/api/v3/{resource}/{relation}?limit=10",
            headers=headers, timeout=2,
        )
        if status != 200:
            continue
        for item in payload.get("data", []):
            attributes, item_type, item_id = item.get("attributes", {}), item.get("type", ""), item.get("id", "")
            domain_name = attributes.get("host_name") or attributes.get("domain")
            if domain_name:
                associations["domains"][domain_name] = attributes
            if attributes.get("ip_address"):
                associations["ips"][attributes["ip_address"]] = attributes
            if relation == "subdomains":
                associations["subdomains"][item_id] = attributes
                continue
            if item_type == "file" or relation in {"communicating_files", "dropped_files"}:
                associations["files"][attributes.get("sha256") or item_id] = attributes
            elif item_type == "ip_address" or attributes.get("ip_address"):
                associations["ips"][attributes.get("ip_address") or item_id] = attributes
            elif item_type == "domain" or attributes.get("host_name") or attributes.get("domain"):
                associations["domains"][attributes.get("host_name") or attributes.get("domain") or item_id] = attributes

    def hydrate(kind, endpoint, needs_details, limit=1):
        for value, attributes in list(associations[kind].items())[:limit]:
            if not needs_details(attributes):
                continue
            status, payload = _request_json(
                f"https://www.virustotal.com/api/v3/{endpoint}/{quote(value, safe='')}",
                headers=headers, timeout=2,
            )
            if status == 200:
                associations[kind][value] = payload.get("data", {}).get("attributes", {})

    hydrate("domains", "domains", lambda details: not ((details.get("first_submission_date") or details.get("first_seen_date")) and details.get("last_analysis_stats") and details.get("last_analysis_results")))
    hydrate("subdomains", "domains", lambda details: not ((details.get("first_submission_date") or details.get("first_seen_date")) and details.get("last_analysis_stats") and details.get("last_analysis_results")))
    hydrate("ips", "ip_addresses", lambda details: not ((details.get("first_submission_date") or details.get("first_seen_date")) and details.get("last_analysis_stats")))
    hydrate("files", "files", lambda details: not (details.get("md5") and (details.get("meaningful_name") or details.get("names")) and details.get("last_analysis_stats")))
    return {
        "domains": [{"value": value, **_vt_dates(attributes), **_vt_stats(attributes)} for value, attributes in sorted(associations["domains"].items())[:20]],
        "subdomains": [{"value": value, **_vt_dates(attributes), **_vt_stats(attributes)} for value, attributes in sorted(associations["subdomains"].items())[:20]],
        "ips": [{"value": value, **_vt_dates(attributes), **_vt_stats(attributes)} for value, attributes in sorted(associations["ips"].items())[:20]],
        "files": [{"sha256": value, "md5": attributes.get("md5", "Unavailable"), "name": attributes.get("meaningful_name") or next(iter(attributes.get("names", [])), "Unavailable"), **_vt_stats(attributes)} for value, attributes in sorted(associations["files"].items())[:20]],
    }


def _local_scan(target, target_type):
    if target_type == "url":
        risk, summary, _mitre = analyze_url(target)
        verdict = "Suspicious" if risk in {"High", "Medium"} else "Clean"
        return _result("local", "Complete", verdict, summary)
    return _result("local", "Complete", "Unknown", f"Local heuristics recorded a {target_type} indicator; no remote content was fetched.")


def _virustotal_scan(target, target_type):
    key = source_api_settings()["virustotal_api_key"]
    if not key:
        return _result("virustotal", "Not configured", "Unknown", "Set VIRUSTOTAL_API_KEY to enable this engine.")
    if target_type != "url":
        endpoint_type = {"domain": "domains", "ip": "ip_addresses", "hash": "files"}[target_type]
        status, payload = _request_json(f"https://www.virustotal.com/api/v3/{endpoint_type}/{quote(target, safe='')}", headers={"x-apikey": key})
        attributes = payload.get("data", {}).get("attributes", {})
        if status != 200:
            return _result("virustotal", "Error", "Unknown", payload.get("error", {}).get("message", payload.get("error", f"HTTP {status}")))
        stats = attributes.get("last_analysis_stats", {})
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "Malicious" if malicious else "Suspicious" if suspicious else "Clean"
        return _result("virustotal", "Complete", verdict, f"{malicious} malicious and {suspicious} suspicious detections.", associations=_vt_associations(target, target_type, {"x-apikey": key}), engine_results=_vt_engine_results(attributes), engine_summary=_vt_engine_summary(stats))
    url_id = urlsafe_b64encode(target.encode()).decode().rstrip("=")
    status, payload = _request_json(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key})
    cached_attributes = payload.get("data", {}).get("attributes", {})
    if status == 200 and cached_attributes.get("last_analysis_stats"):
        stats = cached_attributes["last_analysis_stats"]
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "Malicious" if malicious else "Suspicious" if suspicious else "Clean"
        return _result("virustotal", "Complete", verdict, f"Cached URL verdict: {malicious} malicious and {suspicious} suspicious detections.", associations=_vt_associations(target, target_type, {"x-apikey": key}), engine_results=_vt_engine_results(cached_attributes), engine_summary=_vt_engine_summary(stats))

    headers = {"x-apikey": key, "Content-Type": "application/x-www-form-urlencoded"}
    status, payload = _request_json("https://www.virustotal.com/api/v3/urls", "POST", headers, urlencode({"url": target}).encode())
    analysis_id = payload.get("data", {}).get("id")
    if status not in {200, 201} or not analysis_id:
        return _result("virustotal", "Error", "Unknown", payload.get("error", {}).get("message", payload.get("error", f"HTTP {status}")))
    for attempt in range(6):
        if attempt:
            time.sleep(2)
        status, payload = _request_json(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers={"x-apikey": key})
        attributes = payload.get("data", {}).get("attributes", {})
        if status == 200 and attributes.get("status") == "completed":
            stats = attributes.get("stats", {})
            malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
            verdict = "Malicious" if malicious else "Suspicious" if suspicious else "Clean"
            return _result("virustotal", "Complete", verdict, f"{malicious} malicious and {suspicious} suspicious detections.", engine_results=_vt_engine_results(attributes), engine_summary=_vt_engine_summary(stats))
    return _result("virustotal", "Timed out", "Unknown", "VirusTotal accepted the URL but did not return a completed verdict within the polling window.")


def virustotal_domain_associations(domain):
                                                                                             
    return _virustotal_scan(domain, "domain")


def _kaspersky_scan(target, target_type):
    key = source_api_settings()["kaspersky_otip_api_key"]
    if not key:
        return _result("kaspersky", "Not configured", "Unknown", "Set KASPERSKY_OTIP_API_KEY to enable this engine.")
    endpoint = f"https://opentip.kaspersky.com/api/v1/search/{'url' if target_type == 'url' else target_type}?" + urlencode({"request": target})
    status, payload = _request_json(endpoint, headers={"x-api-key": key})
    if status != 200:
        return _result("kaspersky", "Error", "Unknown", payload.get("error", f"HTTP {status}"))
    zone = str(payload.get("Zone", "Unknown"))
    verdict = "Malicious" if zone.lower() == "red" else "Suspicious" if zone.lower() == "orange" else "Clean" if zone.lower() in {"green", "trusted"} else "Unknown"
    return _result("kaspersky", "Complete", verdict, f"Kaspersky reputation zone: {zone}.")


def _phishtank_scan(target, target_type):
    if target_type != "url":
        return _result("phishtank", "Not supported", "Unknown", "PhishTank checks URL indicators only.")
    app_key = source_api_settings()["phishtank_api_key"]
    data = {"url": target, "format": "json"}
    if app_key:
        data["app_key"] = app_key
    status, payload = _request_json(
        "https://checkurl.phishtank.com/checkurl/", "POST",
        {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Cyberseek/1.0"}, urlencode(data).encode(),
    )
    if status != 200:
        error = str(payload.get("error", f"HTTP {status}"))
        if "browser verification" in error.lower() or "non-json" in error.lower():
            return _result("phishtank", "Unavailable", "Unknown", "PhishTank returned a browser-verification page, so no automated verdict is available.")
        return _result("phishtank", "Error", "Unknown", error[:220])
    findings = payload.get("results", payload)
    in_database, valid = bool(findings.get("in_database")), bool(findings.get("valid"))
    verdict = "Malicious" if in_database and valid else "Clean" if in_database is False else "Unknown"
    summary = "Known, verified phishing URL." if verdict == "Malicious" else "No verified phishing record returned."
    return _result("phishtank", "Complete", verdict, summary, findings.get("phish_detail_page"))


def _talos_lookup(target, target_type):
    if target_type == "hash" and len(target) != 64:
        return _result("talos", "Not supported", "Unknown", "Cisco Talos file reputation accepts SHA-256 hashes only.")
    reference = "https://www.talosintelligence.com/reputation_center/lookup?" + urlencode({"search": target})
    return _result("talos", "External lookup", "Unknown", "Open the Cisco Talos Reputation Center to retrieve the current reputation.", reference)


def _urlhaus_scan(target, target_type):
    key = source_api_settings()["urlhaus_api_key"]
    if not key:
        return _result("urlhaus", "Not configured", "Unknown", "Set URLHAUS_API_KEY to enable this engine.")
    endpoint, field = (
        ("url", "url") if target_type == "url" else
        ("payload", "sha256_hash") if target_type == "hash" else
        ("host", "host")
    )
    status, payload = _request_json(
        f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", "POST",
        {"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"}, urlencode({field: target}).encode(),
    )
    if status != 200:
        return _result("urlhaus", "Error", "Unknown", payload.get("error", payload.get("query_status", f"HTTP {status}")))
    found = payload.get("query_status") == "ok"
    if found:
        threat = payload.get("threat") or payload.get("signature") or "malware distribution"
        return _result("urlhaus", "Complete", "Malicious", f"URLhaus matched known {threat} infrastructure.", "https://urlhaus.abuse.ch/")
    return _result("urlhaus", "Complete", "Clean", "No URLhaus malware-distribution record returned.", "https://urlhaus.abuse.ch/")


def _malwarebazaar_scan(target, target_type):
    if target_type != "hash":
        return _result("malwarebazaar", "Not supported", "Unknown", "MalwareBazaar checks file hashes only.")
    key = source_api_settings()["malwarebazaar_api_key"]
    if not key:
        return _result("malwarebazaar", "Not configured", "Unknown", "Set MALWAREBAZAAR_API_KEY to enable this engine.")
    status, payload = _request_json(
        "https://mb-api.abuse.ch/api/v1/", "POST",
        {"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"}, urlencode({"query": "get_info", "hash": target}).encode(),
    )
    if status != 200:
        return _result("malwarebazaar", "Error", "Unknown", payload.get("error", payload.get("query_status", f"HTTP {status}")))
    findings = payload.get("data", []) if isinstance(payload, dict) else []
    if findings:
        sample = findings[0]
        name = sample.get("file_name") or "unnamed sample"
        family = sample.get("signature") or "unclassified malware"
        return _result("malwarebazaar", "Complete", "Malicious", f"Known malware sample: {name} ({family}).", "https://bazaar.abuse.ch/")
    return _result("malwarebazaar", "Complete", "Clean", "No MalwareBazaar sample matched this hash.", "https://bazaar.abuse.ch/")


def _otx_scan(target, target_type):
    key = source_api_settings()["otx_api_key"]
    if not key:
        return _result("otx", "Not configured", "Unknown", "Set OTX_API_KEY to enable this engine.")
    indicator_type = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[target_type]
    status, payload = _request_json(
        f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{quote(target, safe='')}/general",
        headers={"X-OTX-API-KEY": key},
    )
    if status != 200:
        return _result("otx", "Error", "Unknown", payload.get("detail", payload.get("error", f"HTTP {status}")))
    pulse_count = int(payload.get("pulse_info", {}).get("count", 0))
    verdict = "Malicious" if pulse_count else "Clean"
    return _result("otx", "Complete", verdict, f"Matched {pulse_count} OTX community pulse(s).", "https://otx.alienvault.com/")


def _abuseipdb_scan(target, target_type):
    if target_type != "ip":
        return _result("abuseipdb", "Not supported", "Unknown", "AbuseIPDB checks public IP addresses only.")
    key = source_api_settings()["abuseipdb_api_key"]
    if not key:
        return _result("abuseipdb", "Not configured", "Unknown", "Set ABUSEIPDB_API_KEY to enable this engine.")
    status, payload = _request_json(
        "https://api.abuseipdb.com/api/v2/check?" + urlencode({"ipAddress": target, "maxAgeInDays": 90}),
        headers={"Key": key, "Accept": "application/json"},
    )
    if status != 200:
        return _result("abuseipdb", "Error", "Unknown", payload.get("errors", payload.get("error", f"HTTP {status}")))
    record = payload.get("data", {})
    score, reports = int(record.get("abuseConfidenceScore", 0)), int(record.get("totalReports", 0))
    verdict = "Malicious" if score >= 75 else "Suspicious" if score else "Clean"
    return _result("abuseipdb", "Complete", verdict, f"Abuse confidence {score}/100 from {reports} report(s) in the selected period.", "https://www.abuseipdb.com/check/" + quote(target, safe=""))


ENGINE_HANDLERS = {
    "local": _local_scan, "virustotal": _virustotal_scan, "kaspersky": _kaspersky_scan,
    "phishtank": _phishtank_scan, "talos": _talos_lookup,
    "urlhaus": _urlhaus_scan, "malwarebazaar": _malwarebazaar_scan, "otx": _otx_scan,
    "abuseipdb": _abuseipdb_scan,
}


def selected_reputation_engines(selection):
                                                                                    
    values = selection.split(",") if isinstance(selection, str) else selection or ()
    values = tuple(dict.fromkeys(value.strip() for value in values if value and value.strip()))
    if "all" in values:
        return tuple(ENGINE_HANDLERS)
    return tuple(value for value in values if value in ENGINE_HANDLERS)


def reputation_verdict_summary(results):
    summary = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    for result in results:
        bucket = str(result.get("verdict", "unknown")).lower()
        summary[bucket if bucket in summary else "unknown"] += 1
    summary["total"] = sum(summary.values())
    return summary


def vt_engine_verdict_summary(results):
    summary = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    for result in results:
        bucket = str(result.get("verdict", "unknown")).lower()
        summary[bucket if bucket in summary else "unknown"] += 1
    summary["total"] = sum(summary.values())
    return summary


def reputation_location(report, target):
    candidates = []
    try:
        if ipaddress.ip_address(target).is_global:
            candidates.append(target)
    except ValueError:
        pass
    for item in report.get("associations", {}).get("ips", []):
        candidate = item.get("value") if isinstance(item, dict) else item
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    candidates.append(urlparse(target).hostname or target)
    for candidate in candidates:
        location = geolocate_result("", candidate)
        if location:
            return location
    return None


def reputation_iocs(report, task):
                                                                                 
    iocs, seen = [], set()

    def add(value, indicator_type, source, **metadata):
        value = str(value or "").strip()
        identity = (indicator_type, value.lower())
        if not value or identity in seen:
            return
        seen.add(identity)
        item = {"value": value, "type": indicator_type, "source": source}
        item.update({key: value for key, value in metadata.items() if value not in (None, "", "Unavailable")})
        iocs.append(item)

    target = report.get("target") or task["target"]
    add(target, report.get("target_type") or "indicator", "Lookup target")
    associations = report.get("associations", {})
    for kind, indicator_type in (("domains", "domain"), ("subdomains", "domain"), ("ips", "ip")):
        for entry in associations.get(kind, []):
            if isinstance(entry, dict):
                add(
                    entry.get("value"), indicator_type, "VirusTotal associated intelligence",
                    first_seen=entry.get("first_seen"), last_seen=entry.get("last_seen"),
                    reputation=entry.get("reputation"), malicious_detections=entry.get("malicious"),
                    suspicious_detections=entry.get("suspicious"),
                )
            else:
                add(entry, indicator_type, "VirusTotal associated intelligence")
    for entry in associations.get("files", []):
        if isinstance(entry, dict):
            metadata = {"file_name": entry.get("name"), "malicious_detections": entry.get("malicious"), "suspicious_detections": entry.get("suspicious")}
            add(entry.get("sha256"), "sha256", "VirusTotal associated intelligence", **metadata)
            add(entry.get("md5"), "md5", "VirusTotal associated intelligence", **metadata)
        else:
            add(entry, "sha256", "VirusTotal associated intelligence")
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task": {"id": task["id"], "target": target, "target_type": report.get("target_type"), "status": task["status"]},
        "iocs": iocs,
    }


def merge_vt_engine_summaries(summaries):
    merged = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    for summary in summaries:
        for category in merged:
            merged[category] += int(summary.get(category, 0))
    merged["total"] = sum(merged.values())
    return merged


def refresh_reputation_soc_summary(report):
    summary = report.get("soc_summary") if isinstance(report, dict) else None
    required = {"intelligence", "coverage", "limitations"}
    if isinstance(summary, dict) and required.issubset(summary):
        return False
    report["soc_summary"] = create_soc_summary(report)
    return True


def run_reputation_lookup(target, engine):
    target_type = classify_target(target)
    selected = selected_reputation_engines(engine)
    if not selected:
        raise ValueError("No supported reputation source was selected.")
    def run_engine(engine_name):
        try:
            return ENGINE_HANDLERS[engine_name](target, target_type)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return _result(engine_name, "Error", "Unknown", f"Engine request failed: {str(exc)[:300]}")

    executor = ThreadPoolExecutor(max_workers=min(8, len(selected)))
    futures = {engine_name: executor.submit(run_engine, engine_name) for engine_name in selected}
    done, pending = wait(futures.values(), timeout=18)
    results = []
    for engine_name in selected:
        future = futures[engine_name]
        if future in done:
            results.append(future.result())
        else:
            future.cancel()
            results.append(_result(engine_name, "Timed out", "Unknown", "This source did not respond within 18 seconds."))
    executor.shutdown(wait=False, cancel_futures=True)
    associations = {"domains": {}, "subdomains": {}, "ips": {}, "files": {}}
    for result in results:
        for kind, values in result.get("associations", {}).items():
            if kind not in associations:
                continue
            for value in values:
                identity = (value.get("value") or value.get("sha256")) if isinstance(value, dict) else value
                associations[kind][identity] = value
    vt_source_results = [result for result in results if result["engine"] == ENGINES["virustotal"]]
    vt_results = [entry for result in vt_source_results for entry in result.get("engine_results", [])]
    vt_summary = vt_engine_verdict_summary(vt_results) if vt_results else merge_vt_engine_summaries(result.get("engine_summary", {}) for result in vt_source_results)
    report = {"target": target, "target_type": target_type, "selected_engines": list(selected), "verdict_summary": reputation_verdict_summary(results), "vt_engine_results": vt_results, "vt_verdict_summary": vt_summary, "associations": {kind: list(values.values())[:20] for kind, values in associations.items()}, "results": results}
    refresh_reputation_soc_summary(report)
    return report


def run_reputation_task(database, task_id, target, engine):
    try:
        report = run_reputation_lookup(target, engine)
        report["local_heuristic"] = ingest_local_intelligence(database, task_id, "reputation", report)
        result = json.dumps(report)
        status, error = "Complete", None
    except (OSError, ValueError, KeyError) as exc:
        status, result, error = "Failed", None, str(exc)[:1000]
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE reputation_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?", (status, result, error, datetime.now(timezone.utc).isoformat(), task_id))


def expire_stalled_reputation_tasks(connection):
    cutoff = (datetime.now(timezone.utc).timestamp() - 45)
    connection.execute(
        """UPDATE reputation_tasks
        SET status = 'Failed', error = 'The task timed out before any result was saved.', completed_at = ?
        WHERE status = 'Running' AND CAST(strftime('%s', created_at) AS INTEGER) < ?""",
        (datetime.now(timezone.utc).isoformat(), cutoff),
    )
    connection.commit()


def register_reputation_routes(app, database, db, current_user, login_required):
    @app.route("/analysis/url", methods=["GET", "POST"])
    @app.route("/analysis/reputation", methods=["GET", "POST"])
    @login_required
    def reputation_lookup():
        expire_stalled_reputation_tasks(db())
        if request.method == "POST":
            target = request.form.get("target", "").strip()
            requested_engines = request.form.getlist("engines")
            selected_engines = selected_reputation_engines(requested_engines)
            if not classify_target(target):
                flash("Enter a public URL, hostname, domain, IP address, or supported hash.", "error")
            elif not selected_engines:
                flash("Select one or more supported scanning engines.", "error")
            else:
                engine = "all" if "all" in requested_engines else ",".join(selected_engines)
                task_id = str(uuid.uuid4())
                db().execute(
                    """INSERT INTO reputation_tasks
                    (id, user_id, target, engine, status, result, error, created_at, completed_at, is_private)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (task_id, current_user()["id"], target, engine, "Running", None, None, datetime.now(timezone.utc).isoformat(), None, is_private_task(request.form)),
                )
                db().commit()
                threading.Thread(target=run_reputation_task, args=(database, task_id, target, engine), daemon=True).start()
                flash("Reputation lookup started. Selected external providers will receive this indicator.", "success")
                return redirect(url_for("reputation_lookup"))
        tasks = visible_tasks(db(), "reputation_tasks", current_user()["id"])
        requested_target = request.args.get("target", "").strip() if request.method == "GET" else ""
        return render_template("reputation.html", tasks=tasks, engines=ENGINES, requested_target=requested_target)

    @app.route("/analysis/url/<task_id>")
    @app.route("/analysis/reputation/<task_id>")
    @login_required
    def view_reputation_lookup(task_id):
        expire_stalled_reputation_tasks(db())
        task = visible_task(db(), "reputation_tasks", task_id, current_user()["id"])
        if not task:
            flash("Reputation lookup task not found.", "error")
            return redirect(url_for("reputation_lookup"))
        report = json.loads(task["result"]) if task["result"] else {"results": []}
        retired_sources = {"urlscan", "urlscan.io"}
        report["results"] = [
            result for result in report.get("results", [])
            if str(result.get("engine", "")).strip().lower() not in retired_sources
        ]
        report["selected_engines"] = [
            engine for engine in report.get("selected_engines", [])
            if str(engine).strip().lower() not in retired_sources
        ]
        if task["engine"] == "all":
            report["visible_engine_label"] = "ALL"
        else:
            report["visible_engine_label"] = ", ".join(report["selected_engines"]).upper() or "RETIRED SOURCE"
        report["verdict_summary"] = reputation_verdict_summary(report["results"])
        summary_updated = refresh_reputation_soc_summary(report)
        report.setdefault("vt_engine_results", [])
        report.setdefault("vt_verdict_summary", vt_engine_verdict_summary(report["vt_engine_results"]))
        if summary_updated:
            db().execute("UPDATE reputation_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
            db().commit()
        return render_template("reputation_task.html", task=task, report=report, location=reputation_location(report, task["target"]))

    @app.post("/analysis/url/<task_id>/delete")
    @app.post("/analysis/reputation/<task_id>/delete")
    @login_required
    def delete_reputation_lookup(task_id):
        delete_owned_task(db(), "reputation_tasks", task_id, current_user()["id"])
        db().commit()
        flash("Reputation lookup deleted.", "success")
        return redirect(url_for("reputation_lookup"))

    @app.get("/analysis/url/<task_id>/export/<export_format>")
    @app.get("/analysis/reputation/<task_id>/export/<export_format>")
    @login_required
    def export_reputation_lookup(task_id, export_format):
        task = visible_task(db(), "reputation_tasks", task_id, current_user()["id"])
        if not task:
            flash("Reputation lookup task not found.", "error")
            return redirect(url_for("reputation_lookup"))

        report = json.loads(task["result"]) if task["result"] else {"results": []}
        retired_sources = {"urlscan", "urlscan.io"}
        report["results"] = [
            result for result in report.get("results", [])
            if str(result.get("engine", "")).strip().lower() not in retired_sources
        ]
        report["selected_engines"] = [
            engine for engine in report.get("selected_engines", [])
            if str(engine).strip().lower() not in retired_sources
        ]
        report["verdict_summary"] = reputation_verdict_summary(report["results"])
        summary_updated = refresh_reputation_soc_summary(report)
        report.setdefault("vt_engine_results", [])
        report.setdefault("vt_verdict_summary", vt_engine_verdict_summary(report["vt_engine_results"]))
        if summary_updated:
            db().execute("UPDATE reputation_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
            db().commit()
        location = reputation_location(report, task["target"])
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

        if export_format == "json":
            payload = dict(task)
            payload["report"] = report
            payload["network_location"] = location
            response = make_response(jsonify(payload))
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-reputation-{timestamp}.json"
            return response
        if export_format == "html":
            response = make_response(render_template(
                "reputation_export.html", task=task, report=report,
                location=location, generated_at=datetime.now(timezone.utc),
            ))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-reputation-{timestamp}.html"
            return response

        flash("Unsupported export format.", "error")
        return redirect(url_for("reputation_lookup"))

    @app.get("/analysis/reputation/<task_id>/export/iocs.json")
    @login_required
    def export_reputation_iocs(task_id):
        task = visible_task(db(), "reputation_tasks", task_id, current_user()["id"])
        if not task:
            flash("Reputation lookup task not found.", "error")
            return redirect(url_for("reputation_lookup"))
        if not task["result"]:
            flash("IoCs are available once this reputation lookup has results.", "error")
            return redirect(url_for("view_reputation_lookup", task_id=task_id))
        bundle = reputation_iocs(json.loads(task["result"]), task)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        response = make_response(jsonify(bundle))
        response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-iocs-{timestamp}.json"
        return response
