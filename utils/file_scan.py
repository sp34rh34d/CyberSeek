import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

import pyzipper
from flask import flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from utils.soc_summary import create_file_action_threat_indicators, create_file_sandbox_summary
from utils.local_heuristics import ingest_local_intelligence
from utils.source_config import source_api_settings
from utils.service_config import service_settings
from utils.uploads import protect_upload
from utils.task_access import delete_owned_task, is_private_task, module_history, visible_task


MAX_STATIC_BYTES = 16 * 1024 * 1024
MAX_DYNAMIC_UPLOAD_BYTES = 100 * 1024 * 1024
DYNAMIC_POLL_INTERVAL = 5
# Fresh sandbox detonations (especially Office documents) routinely take several
# minutes; the window is configurable via [service] DYNAMIC_SANDBOX_MINUTES.
MAX_DYNAMIC_POLL_ATTEMPTS = max(12, service_settings().get("DYNAMIC_SANDBOX_MINUTES", 10) * 60 // DYNAMIC_POLL_INTERVAL)
MAX_IOCS = 40
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]{3,2048}", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])", re.IGNORECASE)
DOMAIN_CONTEXT_PATTERN = re.compile(r"(?i)(?:\b(?:domain|host|server|hostname|dns|connect|socket|uri)\s*[:=]\s*|\b(?:connect(?:ion)?\s+to|dns\s+query\s+for)\s+)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})")
IP_PATTERN = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.:])")
DYNAMIC_IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
STATIC_ENGINE_LABEL = "Local static sandbox"
PROVIDER_ENGINES = {"hybrid_analysis": "Hybrid Analysis", "filescan": "Filescan.io"}
FILE_ENGINES = {"local": STATIC_ENGINE_LABEL, **PROVIDER_ENGINES}
HIGH_CONFIDENCE_TLDS = {"com", "net", "org", "edu", "gov", "mil", "int", "io", "ai", "app", "dev", "info", "biz", "me", "co", "us", "uk", "ca", "de", "fr", "es", "it", "nl", "be", "ch", "at", "se", "no", "fi", "dk", "pl", "ru", "ua", "cn", "jp", "kr", "in", "au", "nz", "br", "mx", "ar", "cl", "pe", "za", "ng", "ae", "sa", "il", "tr", "id", "sg", "hk", "tw", "th", "vn", "my", "ph", "pk", "ro", "cz", "sk", "hu", "gr", "pt", "ie", "eu", "online", "site", "xyz", "top", "cc", "ws", "tv", "pro", "mobi", "cloud", "tech", "store", "live", "solutions"}
HYBRID_ENVIRONMENTS = {
    "windows": {"id": "160", "label": "Windows 10 64 bit", "capability": "Dynamic analysis"},
    "linux": {"id": "330", "label": "Linux Ubuntu 24.04 64 bit", "capability": "Dynamic analysis"},
    "android": {"id": "200", "label": "Android Static Analysis", "capability": "Static analysis"},
}


def _sandbox_profile(path, filename):
    suffix = Path(filename).suffix.lower()
    if suffix in {".apk", ".aab", ".dex"}:
        return {"platform": "android", **HYBRID_ENVIRONMENTS["android"]}
    try:
        with Path(path).open("rb") as source:
            magic = source.read(4)
    except OSError:
        magic = b""
    if magic == b"\x7fELF" or suffix in {".elf", ".so", ".sh"}:
        return {"platform": "linux", **HYBRID_ENVIRONMENTS["linux"]}
    return {"platform": "windows", **HYBRID_ENVIRONMENTS["windows"]}


def _hashes(path):
    values = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            for digest in values.values():
                digest.update(block)
    return {name: digest.hexdigest() for name, digest in values.items()}


def _hashes_bytes(content):
    return {name: getattr(hashlib, name)(content).hexdigest() for name in ("md5", "sha1", "sha256")}


class _SeekableZipSource:
                                                                                
    def __init__(self, source):
        self._source = source

    def seekable(self):
        return True

    def __getattr__(self, name):
        return getattr(self._source, name)


def _zip_password_required(source):
                                                                       
    try:
        source.seek(0)
        with pyzipper.AESZipFile(_SeekableZipSource(source)) as archive:
            return any(info.flag_bits & 0x1 for info in archive.infolist())
    except (OSError, RuntimeError, ValueError, pyzipper.zipfile.BadZipFile):
        return False
    finally:
        source.seek(0)


def _valid_zip_password(source, password):
    if not password:
        return False
    try:
        source.seek(0)
        with pyzipper.AESZipFile(_SeekableZipSource(source)) as archive:
            archive.setpassword(password.encode("utf-8"))
            entry = next((item for item in archive.infolist() if not item.is_dir()), None)
            if not entry:
                return True
            with archive.open(entry) as extracted:
                extracted.read(1)
        return True
    except (OSError, RuntimeError, ValueError, UnicodeError, pyzipper.zipfile.BadZipFile):
        return False
    finally:
        source.seek(0)


def _protected_archive_member(path, password, limit):
                                                                                
    if not password:
        raise ValueError("A password is required to inspect this protected archive.")
    try:
        with pyzipper.AESZipFile(path) as archive:
            archive.setpassword(password.encode("utf-8"))
            entry = next((item for item in archive.infolist() if not item.is_dir()), None)
            if not entry:
                raise ValueError("The protected archive does not contain an analyzable file.")
            if entry.file_size > limit:
                raise ValueError(f"The protected archive member exceeds the {limit // (1024 * 1024)} MB analysis limit.")
            with archive.open(entry) as extracted:
                content = extracted.read(limit + 1)
            if len(content) > limit:
                raise ValueError(f"The protected archive member exceeds the {limit // (1024 * 1024)} MB analysis limit.")
            return Path(entry.filename).name or "extracted-sample.bin", content
    except (OSError, RuntimeError, ValueError, UnicodeError, pyzipper.zipfile.BadZipFile) as exc:
        raise ValueError("The supplied archive password could not decrypt its contents.") from exc


def _static_sample(path, password=""):
    path = Path(path)
    with path.open("rb") as source:
        protected = _zip_password_required(source)
    if not protected:
        return path.read_bytes()[:MAX_STATIC_BYTES]
    return _protected_archive_member(path, password, MAX_STATIC_BYTES)[1]


def _format_name(path, sample):
    suffix = Path(path).suffix.lower().lstrip(".") or "unknown"
    if sample.startswith(b"MZ"):
        return "Windows Portable Executable"
    if sample.startswith(b"PK\x03\x04"):
        return "ZIP-compatible archive"
    if sample.startswith(b"%PDF-"):
        return "PDF document"
    if sample.startswith(b"\x7fELF"):
        return "ELF executable"
    if sample.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE compound document"
    return f"{suffix.upper()} file"


def _extract_iocs(sample):
    text = sample.decode("utf-8", "ignore")
    urls = list(dict.fromkeys(match.rstrip(".,;:!?)\\]") for match in URL_PATTERN.findall(text)))[:MAX_IOCS]
    domains = [urlsplit(url).hostname.lower() for url in urls if urlsplit(url).hostname]
    domains.extend(match.lower().rstrip(".") for match in DOMAIN_CONTEXT_PATTERN.findall(text))
    domains = list(dict.fromkeys(domain for domain in domains if _is_high_confidence_domain(domain)))[:MAX_IOCS]
    ips = []
    for candidate in IP_PATTERN.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in ips:
            ips.append(candidate)
    return {"urls": urls[:MAX_IOCS], "domains": domains[:MAX_IOCS], "ips": ips[:MAX_IOCS]}


def _is_high_confidence_domain(value):
    labels = str(value or "").lower().rstrip(".").split(".")
    return len(labels) >= 2 and len(labels[0]) >= 3 and labels[-1] in HIGH_CONFIDENCE_TLDS


def _is_network_url(value):
    parsed = urlsplit(str(value or ""))
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and parsed.hostname.lower() != "attack.mitre.org"


def _extract_strings(sample, source_name="Uploaded file"):
    matches = []
    for match in re.finditer(rb"[\x20-\x7e]{4,}", sample):
        value = match.group().decode("ascii", "ignore").strip()
        if value:
            matches.append({"source": source_name, "offset": f"0x{match.start():08X}", "encoding": "ASCII", "length": len(value), "value": value[:16000], "truncated": len(value) > 16000})
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", sample):
        value = match.group().decode("utf-16le", "ignore").strip()
        if value:
            matches.append({"source": source_name, "offset": f"0x{match.start():08X}", "encoding": "UTF-16LE", "length": len(value), "value": value[:16000], "truncated": len(value) > 16000})
    matches.sort(key=lambda item: int(item["offset"], 16))
    return {"items": matches[:300], "total": len(matches), "truncated": len(matches) > 300}


def _behavior_nodes(filename, sample, iocs):
    lower = sample.lower()
    root = {"id": "sample", "parent": None, "process": filename, "action": "Static sample loaded into isolated inspection profile", "evidence": "No execution was performed.", "mitre": "—", "kind": "root"}
    nodes = [root]
    rules = [
        (b"powershell", "powershell.exe", "PowerShell execution indicator", "T1059.001", "Found the string 'powershell' in static content."),
        (b"cmd.exe", "cmd.exe", "Windows command shell indicator", "T1059.003", "Found the string 'cmd.exe' in static content."),
        (b"createRemoteThread".lower(), "remote process", "Process injection API indicator", "T1055", "Found a CreateRemoteThread API reference."),
        (b"run\\", "registry", "Registry Run Keys / Startup Folder indicator", "T1547.001", "Found a Run-key style registry path."),
        (b"schtasks", "schtasks.exe", "Scheduled task indicator", "T1053.005", "Found the string 'schtasks' in static content."),
        (b"rundll32", "rundll32.exe", "Signed binary proxy execution indicator", "T1218.011", "Found the string 'rundll32' in static content."),
        (b"@wanadecryptor@", "WanaDecryptor", "WannaCry ransomware family marker", "T1486", "Found the high-confidence WanaDecryptor marker in static content."),
        (b"mssecsvc.exe", "mssecsvc.exe", "WannaCry propagation component marker", "T1486", "Found the mssecsvc.exe WannaCry component marker in static content."),
    ]
    for index, (needle, process, action, mitre, evidence) in enumerate(rules, 1):
        if needle.lower() in lower:
            nodes.append({"id": f"action-{index}", "parent": "sample", "process": process, "action": action, "evidence": evidence, "mitre": mitre, "kind": "inferred"})
    for index, value in enumerate(iocs["urls"] + iocs["domains"] + iocs["ips"], len(nodes) + 1):
        nodes.append({"id": f"network-{index}", "parent": "sample", "process": filename, "action": "Embedded network indicator", "evidence": f"Static content references {value}.", "mitre": "T1071.001", "kind": "inferred"})
    if len(nodes) == 1:
        nodes.append({"id": "action-none", "parent": "sample", "process": "static-inspector", "action": "No behavior-specific static indicators", "evidence": "No supported behavior patterns were found in the inspected content.", "mitre": "—", "kind": "neutral"})
    return nodes


def _static_family_signal(sample):
    lower = sample.lower()
    markers = (b"@wanadecryptor@", b"mssecsvc.exe", b"wncry", b"wannacry")
    hits = [marker.decode("ascii", "ignore") for marker in markers if marker in lower]
    return {"family": "WannaCry", "markers": hits} if b"@wanadecryptor@" in lower or len(hits) >= 2 else None


def _local_reputation(risky_actions, family_signal=None):
    if family_signal:
        return {"state": "Complete", "verdict": "Malicious", "detail": f"Local static assessment found high-confidence {family_signal['family']} family markers: {', '.join(family_signal['markers'])}.", "malicious": 1, "suspicious": 0, "clean": 0, "engines": []}
    verdict = "Suspicious" if risky_actions else "Clean"
    return {"state": "Complete", "verdict": verdict, "detail": "Local static assessment only; no external provider was queried.", "malicious": 0, "suspicious": int(bool(risky_actions)), "clean": int(not risky_actions), "engines": []}


def _virustotal_reputation(sha256):
    key = source_api_settings().get("virustotal_api_key", "").strip()
    if not key:
        return {"state": "Not configured", "verdict": "Unknown", "detail": "Configure a VirusTotal API key in Source APIs.", "malicious": 0, "suspicious": 0, "clean": 0, "engines": []}
    try:
        query = Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key, "Accept": "application/json"})
        with urlopen(query, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious, suspicious, clean = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)), int(stats.get("harmless", 0))
        verdict = "Malicious" if malicious else "Suspicious" if suspicious else "Clean" if stats else "Unknown"
        engines = sorted(name for name, result in attributes.get("last_analysis_results", {}).items() if result.get("category") in {"malicious", "suspicious"})
        return {"state": "Complete", "verdict": verdict, "detail": "Cached VirusTotal file reputation.", "malicious": malicious, "suspicious": suspicious, "clean": clean, "engines": engines[:30]}
    except HTTPError as exc:
        if exc.code == 404:
            return {"state": "Complete", "verdict": "Unknown", "detail": "VirusTotal has no prior record for this file hash.", "malicious": 0, "suspicious": 0, "clean": 0, "engines": []}
        return {"state": "Unavailable", "verdict": "Unknown", "detail": f"VirusTotal returned HTTP {exc.code}.", "malicious": 0, "suspicious": 0, "clean": 0}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"state": "Unavailable", "verdict": "Unknown", "detail": f"VirusTotal lookup unavailable: {str(exc)[:160]}", "malicious": 0, "suspicious": 0, "clean": 0}


def _provider_reputation(engine, sha256, risky_actions):
    if engine == "local":
        return _local_reputation(risky_actions)
    settings = source_api_settings()
    key_name = "hybrid_analysis_api_key" if engine == "hybrid_analysis" else "filescan_api_key"
    key = settings.get(key_name, "").strip()
    if not key:
        return {"state": "Not configured", "verdict": "Unknown", "detail": f"Configure the {PROVIDER_ENGINES[engine]} API key in Source APIs.", "malicious": 0, "suspicious": 0, "clean": 0, "engines": []}
    if engine == "hybrid_analysis":
        endpoint = "https://www.hybrid-analysis.com/api/v2/search/hash?" + urlencode({"hash": sha256})
        headers = {"api-key": key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
    else:
        endpoint = "https://www.filescan.io/api/reputation/hash?" + urlencode({"hash": sha256})
        headers = {"X-Api-Key": key, "Accept": "application/json"}
    try:
        with urlopen(Request(endpoint, headers=headers), timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        item = payload[0] if isinstance(payload, list) and payload else payload.get("data", payload) if isinstance(payload, dict) else {}
        raw = str(item.get("verdict") or item.get("threat_level") or item.get("classification") or "Unknown").lower()
        verdict = "Malicious" if any(word in raw for word in ("malicious", "malware", "suspicious", "high", "malicious")) else "Clean" if any(word in raw for word in ("clean", "benign", "safe", "low")) else "Unknown"
        if "suspicious" in raw or "medium" in raw:
            verdict = "Suspicious"
        score = int(item.get("score") or item.get("threat_score") or 0) if str(item.get("score") or item.get("threat_score") or "").isdigit() else 0
        return {"state": "Complete", "verdict": verdict, "detail": f"Known-hash result from {PROVIDER_ENGINES[engine]}.", "malicious": int(verdict == "Malicious"), "suspicious": int(verdict == "Suspicious"), "clean": int(verdict == "Clean"), "engines": [], "score": score}
    except HTTPError as exc:
        return {"state": "Unavailable", "verdict": "Unknown", "detail": f"{PROVIDER_ENGINES[engine]} returned HTTP {exc.code}.", "malicious": 0, "suspicious": 0, "clean": 0, "engines": []}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"state": "Unavailable", "verdict": "Unknown", "detail": f"{PROVIDER_ENGINES[engine]} lookup unavailable: {str(exc)[:160]}", "malicious": 0, "suspicious": 0, "clean": 0, "engines": []}


def _multipart_file_request(endpoint, fields, path, filename, headers):
    boundary = f"----Cyberseek{uuid.uuid4().hex}"
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode("utf-8"))
    body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode("utf-8"))
    body.extend(Path(path).read_bytes())
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    request_headers = {**headers, "Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))}
    with urlopen(Request(endpoint, data=bytes(body), headers=request_headers, method="POST"), timeout=45) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _http_error_context(exc):
    try:
        detail = re.sub(r"\s+", " ", exc.read(600).decode("utf-8", "replace")).strip()
    except OSError:
        detail = ""
    if detail.startswith("<!DOCTYPE") or detail.startswith("<html"):
        return "The provider returned an HTML error page."
    return detail[:220]


def _hybrid_dynamic_submission(path, filename, key, profile):
    headers = {"api-key": key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
    endpoints = ("https://www.hybrid-analysis.com/api/v2/submit/file", "https://hybrid-analysis.com/api/v2/submit/file")
    last_error = None
    for endpoint in endpoints:
        try:
            return _multipart_file_request(endpoint, {"environment_id": profile["id"]}, path, filename, headers)
        except HTTPError as exc:
            last_error = exc
            if exc.code != 404:
                raise
    raise last_error


def _dynamic_verdict(payload):
    text = json.dumps(payload, ensure_ascii=False).lower()
    if any(token in text for token in ("malicious", "malware", "high risk", "high-risk")):
        return "Malicious"
    if any(token in text for token in ("suspicious", "medium risk", "medium-risk")):
        return "Suspicious"
    if any(token in text for token in ("clean", "benign", "no threat")):
        return "Clean"
    return "Unknown"


def _provider_dynamic_verdict(payload):
    candidates = []
    for path, value in _walk_dynamic_payload(payload):
        if path and path[-1] in {"verdict", "threat_level", "classification", "risk_level", "detection"}:
            candidates.append(str(value).strip().lower())
    verdicts = []
    for value in candidates:
        if value in {"5", "malicious", "malware", "high", "high risk", "high-risk"}:
            verdicts.append("Malicious")
        elif value in {"4", "suspicious", "medium", "medium risk", "medium-risk"}:
            verdicts.append("Suspicious")
        elif value in {"1", "2", "3", "clean", "benign", "safe", "no threat", "no specific threat"}:
            verdicts.append("Clean")
    for verdict in ("Malicious", "Suspicious", "Clean"):
        if verdict in verdicts:
            return verdict
    return _dynamic_verdict(payload)


def _mitre_for_dynamic_action(value):
    techniques = _mitre_techniques_for_dynamic_action(value)
    return techniques[0]["display"] if techniques else "—"


MITRE_TECHNIQUE_DETAILS = {
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery", "description": "The command can identify reachable remote systems by IP address or hostname, which may support later lateral-movement decisions."},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "description": "PowerShell can execute commands and scripts on Windows, including encoded or remotely delivered content."},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution", "description": "The Windows command shell can execute operating-system commands and control local system behavior."},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution", "description": "Visual Basic script interpreters can execute script content on Windows."},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "description": "Process-injection APIs can be used to run code in the address space of another process."},
    "T1053.005": {"name": "Scheduled Task/Job", "tactic": "Execution", "description": "Scheduled tasks can trigger program execution at a chosen time or event."},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion", "description": "Rundll32 may proxy execution of DLL exports using a signed Windows binary."},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence", "description": "Run keys and startup folders can establish execution when a user logs on."},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "description": "The observed behavior may transfer tools or payloads from a remote system."},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "description": "Decoding or deobfuscation can reveal or reconstruct hidden content before execution."},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery", "description": "The command can enumerate running processes on the local system."},
}


def _mitre_techniques_for_dynamic_action(value):
    text = value.lower()
    mappings = (
        (("ping.exe", "launches program ping", " ping ", "ping -", "ping /"), "T1018"),
        (("powershell", "invoke-expression", "invoke-command"), "T1059.001 · PowerShell"),
        (("cmd.exe", "command shell", "/c "), "T1059.003 · Windows Command Shell"),
        (("wscript", "cscript", ".vbs", "visual basic"), "T1059.005 · Visual Basic"),
        (("createRemoteThread".lower(), "virtualallocex", "process injection", "process hollow"), "T1055 · Process Injection"),
        (("schtasks", "scheduled task"), "T1053.005 · Scheduled Task/Job"),
        (("rundll32",), "T1218.011 · Rundll32"),
        (("registry", "currentversion\\run", "startup folder"), "T1547.001 · Registry Run Keys / Startup Folder"),
        (("download", "urlmon", "invoke-webrequest", "wget", "curl"), "T1105 · Ingress Tool Transfer"),
        (("base64", "decode", "deobfuscat", "xor"), "T1140 · Deobfuscate/Decode Files or Information"),
        (("tasklist", "enumerate process", "process discovery"), "T1057 · Process Discovery"),
    )
    matches = []
    for terms, mitre in mappings:
        if any(term in text for term in terms):
            technique_id = mitre.split(" ", 1)[0]
            detail = MITRE_TECHNIQUE_DETAILS.get(technique_id, {})
            matches.append({"id": technique_id, "name": detail.get("name", mitre.split(" · ", 1)[-1]), "tactic": detail.get("tactic", "Unclassified"), "description": detail.get("description", "Observed behavior mapped by the local dynamic-analysis rule."), "display": f"{technique_id} · {detail.get('name', mitre.split(' · ', 1)[-1])}"})
    return list({item["id"]: item for item in matches}.values())


def _dynamic_action_severity(value, mitre):
                                                                              
    text = value.lower()
    high_signals = (
        "createremotethread", "virtualallocex", "process injection", "process hollow",
        "currentversion\\run", "startup folder", "download", "invoke-webrequest",
        "curl", "wget", "base64", "deobfuscat", "xor", " -enc", "-encodedcommand",
    )
    if any(signal in text for signal in high_signals):
        return "high"
    if mitre != "—":
        return "medium"
    return "low"


def _normalise_dynamic_actions(actions):
                                                                            
    changed = False
    for action in actions:
        action_changed = False
        command = str(action.get("command") or action.get("value") or "")
        action.setdefault("action", action.get("kind") or "Observed action")
        action.setdefault("command", command)
        techniques = action.get("mitre_techniques")
        if not isinstance(techniques, list):
            techniques = _mitre_techniques_for_dynamic_action(command)
            action["mitre_techniques"] = techniques
            changed = True
            action_changed = True
        mapped = techniques[0]["display"] if techniques else "—"
        if action.get("mitre") != mapped:
            action["mitre"] = mapped
            changed = True
            action_changed = True
        if not action.get("severity") or action_changed:
            action["severity"] = _dynamic_action_severity(command, mapped)
            changed = True
    return actions, changed


def _submission_id(payload):
    if not isinstance(payload, dict):
        return ""
    for key in ("job_id", "flow_id", "submission_id", "scan_id", "id"):
        value = payload.get(key)
        if value:
            return str(value)
    for value in payload.values():
        if isinstance(value, dict):
            identifier = _submission_id(value)
            if identifier:
                return identifier
    return ""


def _dynamic_fields(payload):
    if not isinstance(payload, dict):
        return []
    fields = []
    for key in ("job_id", "flow_id", "submission_id", "scan_id", "id", "state", "status", "verdict", "threat_score", "environment_id", "analysis_start_time", "analysis_end_time"):
        value = payload.get(key)
        if isinstance(value, (str, int, float, bool)):
            fields.append({"label": key.replace("_", " ").title(), "value": str(value)[:300], "tone": _dynamic_field_tone(key, value)})
    return fields[:10]


def _dynamic_field_tone(key, value):
    if key in {"verdict", "threat_level", "classification", "risk_level", "detection"}:
        verdict = _provider_dynamic_verdict({key: value})
        return {"Malicious": "high", "Suspicious": "medium", "Clean": "low"}.get(verdict, "")
    if key == "threat_score":
        try:
            score = float(value)
        except (TypeError, ValueError):
            return ""
        if (score >= 7 and score <= 10) or score >= 70:
            return "high"
        if (score >= 4 and score <= 10) or score >= 30:
            return "medium"
        return "low"
    return ""


def _apply_dynamic_field_tones(fields):
    for field in fields:
        label = str(field.get("label", "")).lower().replace(" ", "_")
        field["tone"] = field.get("tone") or _dynamic_field_tone(label, field.get("value"))
    return fields


def _walk_dynamic_payload(value, path=()):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield from _walk_dynamic_payload(nested, path + (str(key).lower(),))
    elif isinstance(value, list):
        for nested in value[:300]:
            yield from _walk_dynamic_payload(nested, path)
    else:
        yield path, value


def _dynamic_actions(payload):
    hints = ("process", "action", "behavior", "command", "api", "call", "operation", "event", "activity")
    ignored = ("hash", "sha", "md5", "id", "token", "url", "domain", "ip")
    actions, seen = [], set()
    for path, value in _walk_dynamic_payload(payload):
        if not isinstance(value, (str, int, float)) or not path:
            continue
        key = path[-1]
        if not any(hint in key for hint in hints) or any(hint in key for hint in ignored):
            continue
        text = str(value).strip().replace("\x00", " ")
        if not text or len(text) > 700 or text.lower() in seen:
            continue
        seen.add(text.lower())
        mitre_techniques = _mitre_techniques_for_dynamic_action(text)
        mitre = mitre_techniques[0]["display"] if mitre_techniques else "—"
        actions.append({
            "kind": key.replace("_", " ").title(),
            "value": text,
            "action": key.replace("_", " ").title(),
            "command": text,
            "mitre": mitre,
            "mitre_techniques": mitre_techniques,
            "severity": _dynamic_action_severity(text, mitre),
        })
        if len(actions) == 80:
            break
    return actions


def _dynamic_network(payload):
    urls, domains, ips = [], [], []
    network_hints = ("network", "request", "url", "uri", "domain", "host", "dns", "ip", "remote", "destination", "connection", "socket")
    for path, value in _walk_dynamic_payload(payload):
        if not isinstance(value, str):
            continue
        path_is_network = any(any(hint in part for hint in network_hints) for part in path)
        command_is_network = path[-1] in {"command", "command_line", "action", "process"} and bool(re.search(r"\b(?:ping|curl|wget|nslookup|dig|invoke-webrequest|socket|connect)\b", value, re.IGNORECASE))
        if path_is_network or command_is_network:
            urls.extend(match.rstrip(".,;:!?)\\]") for match in URL_PATTERN.findall(value) if _is_network_url(match))
            domains.extend(match.lower().rstrip(".") for match in DOMAIN_PATTERN.findall(value) if _is_high_confidence_domain(match) and match.lower() != "attack.mitre.org")
        for candidate in DYNAMIC_IP_PATTERN.findall(value):
            try:
                ipaddress.ip_address(candidate)
                if path_is_network or command_is_network:
                    ips.append(candidate)
            except ValueError:
                continue
    requests = []
    for kind, values in (("URL", urls), ("Domain", domains), ("IP address", ips)):
        for value in dict.fromkeys(values):
            if kind == "Domain" and any(value in url for url in urls):
                continue
            requests.append({"kind": kind, "value": value})
            if len(requests) == 100:
                return requests
    return requests


def _dynamic_ip_reputation(ip_value):
                                                                               
    connection = {
        "ip": ip_value, "country": "Unavailable", "owner": "Unavailable", "isp": "Unavailable",
        "reputation": "Unknown", "malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0,
        "detail": "",
    }
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        connection["detail"] = "Invalid IP address returned by the sandbox."
        return connection
    if not address.is_global:
        connection.update({
            "country": "Private / non-public", "owner": "Private address space", "isp": "Not applicable",
            "detail": "Private and non-public addresses are listed but never sent to external enrichment services.",
        })
        return connection

    try:
        with urlopen(f"https://ipwho.is/{ip_value}", timeout=6) as response:
            location = json.loads(response.read().decode("utf-8", "replace"))
        if location.get("success", True):
            connection["country"] = location.get("country") or "Unavailable"
            provider = location.get("connection") or {}
            connection["owner"] = provider.get("org") or provider.get("isp") or "Unavailable"
            connection["isp"] = provider.get("isp") or "Unavailable"
        else:
            connection["detail"] = "Public geolocation data was unavailable."
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        connection["detail"] = "Public geolocation data was unavailable."

    key = source_api_settings().get("virustotal_api_key", "").strip()
    if not key:
        connection["detail"] = (connection["detail"] + " " if connection["detail"] else "") + "VirusTotal API key is not configured."
        return connection
    try:
        query = Request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_value}", headers={"x-apikey": key, "Accept": "application/json"})
        with urlopen(query, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        clean = int(stats.get("harmless", 0) or 0)
        unknown = int(stats.get("undetected", 0) or 0)
        reputation = "Malicious" if malicious else "Suspicious" if suspicious else "Clean" if clean else "Unknown"
        connection.update({"reputation": reputation, "malicious": malicious, "suspicious": suspicious, "clean": clean, "unknown": unknown})
    except HTTPError as exc:
        connection["detail"] = (connection["detail"] + " " if connection["detail"] else "") + f"VirusTotal returned HTTP {exc.code}."
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        connection["detail"] = (connection["detail"] + " " if connection["detail"] else "") + "VirusTotal reputation was unavailable."
    return connection


def _dynamic_network_connections(network_requests):
    ips = list(dict.fromkeys(item["value"] for item in network_requests if item.get("kind") == "IP address"))
    if not ips:
        return []
    with ThreadPoolExecutor(max_workers=min(6, len(ips))) as executor:
        enriched = list(executor.map(_dynamic_ip_reputation, ips))
    return enriched


def _dynamic_threat_indicators(verdict, actions):
    indicators = []
    if verdict in {"Malicious", "Suspicious"}:
        indicators.append({"severity": verdict.lower(), "label": "Provider verdict", "value": f"{verdict} behavior reported by the external sandbox."})
    if not indicators:
        indicators.append({"severity": "low", "label": "No confirmed threat indicator", "value": "The provider has not returned a malicious, suspicious, or MITRE-mapped observation."})
    return indicators


def _static_triage_assessment(report):
                                                                                
    sources = {
        "Static sandbox": (report.get("static_reputation") or {}).get("verdict", "Unknown"),
        "File hash reputation": (report.get("hash_reputation") or {}).get("verdict", "Unknown"),
        "Provider hash reputation": (report.get("reputation") or {}).get("verdict", "Unknown"),
    }
    values = [str(value).title() for value in sources.values()]
    verdict = "Malicious" if "Malicious" in values else "Suspicious" if "Suspicious" in values or report.get("risk") == "Medium" else "Clean" if "Clean" in values and report.get("risk") == "Low" else "Unknown"
    return {"verdict": verdict, "risk": report.get("risk", "Unknown"), "sources": sources}


def _dynamic_result(provider, payload, state="Complete", detail=None, static_assessment=None):
    verdict = _provider_dynamic_verdict(payload)
    actions = _dynamic_actions(payload)
    network_requests = _dynamic_network(payload)
    result = {
        "provider": PROVIDER_ENGINES[provider], "provider_key": provider, "state": state,
        "verdict": verdict, "detail": detail or f"Dynamic sandbox result from {PROVIDER_ENGINES[provider]}.",
        "submission_id": _submission_id(payload), "fields": _dynamic_fields(payload),
        "actions": actions, "network_requests": network_requests,
        "network_connections": _dynamic_network_connections(network_requests) if state == "Complete" else [],
        "threat_indicators": _dynamic_threat_indicators(verdict, actions),
        "static_assessment": static_assessment or {},
        "ai_static_verdict": (static_assessment or {}).get("verdict", "Unknown"),
    }
    if state == "Complete":
        # Two back-to-back Gemini calls (vs. reputation lookup's one) double the odds of
        # landing in the same brief provider-side overload window. A short stagger between
        # them doesn't fix an external outage, but it does reduce the chance both calls hit
        # the exact same bad moment.
        result["ai_summary"] = create_file_sandbox_summary(static_assessment, verdict, actions)
        time.sleep(1.5)
        result["ai_threat_indicators"] = create_file_action_threat_indicators(actions, verdict, static_assessment)
    else:
        result["ai_summary"] = {}
        result["ai_threat_indicators"] = []
    return result


def _dynamic_retry(dynamic, detail):
    attempts = int(dynamic.get("poll_attempts", 0)) + 1
    if attempts >= MAX_DYNAMIC_POLL_ATTEMPTS:
        return {**dynamic, "state": "Unavailable", "poll_attempts": attempts, "detail": f"{detail} Dynamic report polling stopped after {MAX_DYNAMIC_POLL_ATTEMPTS} attempts."}
    return {**dynamic, "state": "Queued", "poll_attempts": attempts, "detail": detail}


def _provider_state_is_pending(value):
    state = str(value or "").strip().lower()
    return any(marker in state for marker in ("queued", "pending", "running", "processing", "in_progress", "in progress", "created"))


def _stored_dynamic_is_pending(dynamic):
    if _provider_state_is_pending(dynamic.get("state")):
        return True
    return any(field.get("label", "").lower() in {"state", "status"} and _provider_state_is_pending(field.get("value")) for field in dynamic.get("fields", []))


def _dynamic_timed_out(dynamic):
    """A dynamic scan whose polling window expired while the sandbox was still working.

    Distinct from a genuinely unavailable result (not configured, provider error): the
    sample was accepted and has a submission id, so re-opening the task can pick up the
    now-ready report instead of leaving it stuck as failed.
    """
    if str(dynamic.get("state") or "").strip().lower() != "unavailable":
        return False
    detail = str(dynamic.get("detail") or "").lower()
    timed_out = any(marker in detail for marker in ("did not complete", "did not finish", "polling stopped"))
    return timed_out and bool(dynamic.get("submission_id") or dynamic.get("sample_sha256") or dynamic.get("provider_key") == "hybrid_analysis")


def _dynamic_submission_file(path, filename, file_password):
                                                                                 
    with Path(path).open("rb") as source:
        protected = _zip_password_required(source)
    if not protected:
        return Path(path), filename, None
    member_name, content = _protected_archive_member(path, file_password, MAX_DYNAMIC_UPLOAD_BYTES)
    suffix = Path(member_name).suffix
    descriptor, temporary_path = tempfile.mkstemp(prefix="cyberseek_dynamic_", suffix=suffix)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
    except OSError:
        Path(temporary_path).unlink(missing_ok=True)
        raise
    return Path(temporary_path), secure_filename(member_name) or filename, Path(temporary_path)


def _submit_dynamic_sandbox(provider, path, filename, file_password="", sample_sha256=""):
    submission_path, submission_filename, temporary_path = _dynamic_submission_file(path, filename, file_password)
    size = submission_path.stat().st_size
    if size > MAX_DYNAMIC_UPLOAD_BYTES:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        return {"provider": PROVIDER_ENGINES[provider], "provider_key": provider, "state": "Unavailable", "verdict": "Unknown", "detail": "The file exceeds the 100 MB dynamic-submission limit.", "submission_id": "", "fields": []}
    settings = source_api_settings()
    key_name = "hybrid_analysis_api_key" if provider == "hybrid_analysis" else "filescan_api_key"
    key = settings.get(key_name, "").strip()
    if not key:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        return {"provider": PROVIDER_ENGINES[provider], "provider_key": provider, "state": "Not configured", "verdict": "Unknown", "detail": f"Configure the {PROVIDER_ENGINES[provider]} API key in Source APIs before submitting a file.", "submission_id": "", "fields": []}
    try:
        profile = _sandbox_profile(submission_path, submission_filename)
        if provider == "hybrid_analysis":
            payload = _hybrid_dynamic_submission(submission_path, submission_filename, key, profile)
        else:
            payload = _multipart_file_request("https://www.filescan.io/api/scan/file", {}, submission_path, submission_filename, {"X-Api-Key": key, "Accept": "application/json"})
        result = _dynamic_result(provider, payload, state="Queued", detail=f"File submitted to {PROVIDER_ENGINES[provider]} for external {profile['capability'].lower()}.")
        result["fields"].extend([
            {"label": "Submission profile", "value": profile["label"], "tone": ""},
            {"label": "Analysis capability", "value": profile["capability"], "tone": ""},
        ])
        result["sample_sha256"] = sample_sha256
        result["environment_id"] = profile["id"]
        if temporary_path:
            result["detail"] += " The password-protected archive was decrypted locally; only its extracted member was submitted."
        result["poll_attempts"] = 0
        if not result["submission_id"]:
            result["state"] = "Complete"
            result["detail"] = f"{PROVIDER_ENGINES[provider]} accepted the dynamic submission. No polling identifier was returned."
        return result
    except HTTPError as exc:
        context = _http_error_context(exc)
        if provider == "hybrid_analysis" and exc.code == 404:
            detail = "Hybrid Analysis did not expose dynamic submission for this credential or environment. Verify that the API key has sandbox-submission access and that environment 160 is available to the account."
        else:
            detail = f"{PROVIDER_ENGINES[provider]} rejected the dynamic submission (HTTP {exc.code})."
        if context:
            detail = f"{detail} Provider detail: {context}"
        return {"provider": PROVIDER_ENGINES[provider], "provider_key": provider, "state": "Unavailable", "verdict": "Unknown", "detail": detail, "submission_id": "", "fields": []}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"provider": PROVIDER_ENGINES[provider], "provider_key": provider, "state": "Unavailable", "verdict": "Unknown", "detail": f"{PROVIDER_ENGINES[provider]} dynamic submission unavailable: {str(exc)[:160]}", "submission_id": "", "fields": []}
    finally:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)


def _hybrid_report_candidates(dynamic):
                                                                               
    candidates = [dynamic.get("submission_id"), dynamic.get("report_id")]
    sample_sha256 = str(dynamic.get("sample_sha256") or "").lower()
    environment_id = str(dynamic.get("environment_id") or "").strip()
    if re.fullmatch(r"[a-f0-9]{64}", sample_sha256) and environment_id.isdigit():
        candidates.append(f"{sample_sha256}:{environment_id}")
    return list(dict.fromkeys(candidate for candidate in candidates if candidate))


def _hybrid_summary(dynamic, headers):
                                                                                
    last_error = None
    for identifier in _hybrid_report_candidates(dynamic):
        endpoint = f"https://www.hybrid-analysis.com/api/v2/report/{identifier}/summary"
        try:
            with urlopen(Request(endpoint, headers=headers), timeout=20) as response:
                return json.loads(response.read().decode("utf-8", "replace")), identifier
        except HTTPError as exc:
            last_error = exc
            if exc.code not in {404, 410}:
                raise
    if last_error:
        raise last_error
    raise ValueError("Hybrid Analysis did not return a usable report identifier.")


def _refresh_dynamic_sandbox(dynamic):
    provider, submission_id = dynamic.get("provider_key"), dynamic.get("submission_id")
    if provider not in PROVIDER_ENGINES or not submission_id:
        return dynamic
    settings = source_api_settings()
    try:
        if provider == "hybrid_analysis":
            key = settings.get("hybrid_analysis_api_key", "").strip()
            headers = {"api-key": key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
        else:
            key = settings.get("filescan_api_key", "").strip()
            endpoint, headers = f"https://www.filescan.io/api/scan/{submission_id}/report", {"X-Api-Key": key, "Accept": "application/json"}
        if not key:
            return {**dynamic, "state": "Not configured", "detail": f"The {PROVIDER_ENGINES[provider]} API key is no longer configured."}
        if provider == "hybrid_analysis":
            payload, report_identifier = _hybrid_summary(dynamic, headers)
        else:
            with urlopen(Request(endpoint, headers=headers), timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
            report_identifier = submission_id
        state_text = str(payload.get("state") or payload.get("status") or "").lower() if isinstance(payload, dict) else ""
        pending = _provider_state_is_pending(state_text)
        if not pending and provider == "hybrid_analysis":
            try:
                report_endpoint = f"https://www.hybrid-analysis.com/api/v2/report/{report_identifier}/report/json"
                with urlopen(Request(report_endpoint, headers=headers), timeout=30) as response:
                    full_payload = json.loads(response.read().decode("utf-8", "replace"))
                if full_payload:
                    payload = full_payload
            except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
                pass
        result = _dynamic_result(provider, payload, state="Queued" if pending else "Complete", detail=f"Dynamic sandbox result from {PROVIDER_ENGINES[provider]}." if not pending else f"{PROVIDER_ENGINES[provider]} is still processing the submitted file.", static_assessment=dynamic.get("static_assessment"))
        result["submission_id"] = result["submission_id"] or submission_id
        if provider == "hybrid_analysis":
            result["report_id"] = report_identifier
            result["sample_sha256"] = dynamic.get("sample_sha256", "")
            result["environment_id"] = dynamic.get("environment_id", "")
        if pending:
            attempts = int(dynamic.get("poll_attempts") or 0) + 1
            if attempts >= MAX_DYNAMIC_POLL_ATTEMPTS:
                return {**result, "state": "Unavailable", "poll_attempts": attempts, "detail": f"{PROVIDER_ENGINES[provider]} did not complete within the polling window. Reopen this task to resume polling."}
            result["poll_attempts"] = attempts
        return result
    except HTTPError as exc:
        if exc.code in {404, 409, 425}:
            return _dynamic_retry(dynamic, f"{PROVIDER_ENGINES[provider]} is preparing the dynamic report.")
        if provider == "hybrid_analysis" and exc.code == 410:
            return {**dynamic, "state": "Unavailable", "detail": "Hybrid Analysis no longer retains this dynamic report, or its report reference expired before retrieval. Local static findings remain available; submit the file again to request a new dynamic run."}
        return {**dynamic, "state": "Unavailable", "detail": f"{PROVIDER_ENGINES[provider]} report retrieval returned HTTP {exc.code}."}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return _dynamic_retry(dynamic, f"Waiting for {PROVIDER_ENGINES[provider]} report: {str(exc)[:120]}")


def run_file_scan(path, filename, provider="local", analysis_mode="static", file_password=""):
    path = Path(path)
    with path.open("rb") as source:
        protected_archive = _zip_password_required(source)
    sample = _static_sample(path, file_password)
    inspected_filename = filename
    if protected_archive:
        inspected_filename, _ = _protected_archive_member(path, file_password, MAX_STATIC_BYTES)
        hashes = _hashes_bytes(sample)
    else:
        hashes = _hashes(path)
    iocs = _extract_iocs(sample)
    strings = _extract_strings(sample, inspected_filename)
    nodes = _behavior_nodes(inspected_filename, sample, iocs)
    risky_actions = sum(node["kind"] == "inferred" and node["mitre"] != "—" for node in nodes)
    family_signal = _static_family_signal(sample)
    static_reputation = _local_reputation(risky_actions, family_signal)
    reputation = _provider_reputation(provider, hashes["sha256"], risky_actions)
    vt_reputation = _virustotal_reputation(hashes["sha256"])
    risk = "High" if static_reputation["verdict"] == "Malicious" or reputation["verdict"] == "Malicious" or risky_actions >= 3 else "Medium" if static_reputation["verdict"] == "Suspicious" or reputation["verdict"] == "Suspicious" or risky_actions else "Low"
    return {
        "filename": filename, "inspected_filename": inspected_filename, "size": path.stat().st_size, "format": _format_name(inspected_filename, sample), "inspected_bytes": len(sample),
        "analysis_mode": analysis_mode, "hashes": hashes, "strings": strings["items"], "string_count": strings["total"], "strings_truncated": strings["truncated"], "static_reputation": static_reputation, "hash_reputation": vt_reputation, "reputation": reputation, "provider": PROVIDER_ENGINES.get(provider), "engine": FILE_ENGINES[provider], "iocs": iocs, "process_tree": nodes, "risk": risk,
        "notice": "Static sandbox profile: the uploaded file was never executed. Process actions are behavior hypotheses inferred from static evidence." + (f" Protected archive member {inspected_filename} was inspected with the supplied password, which is not stored." if protected_archive else ""),
    }


def _file_ioc_indicators(report):
    entries, seen = [], set()

    def add(kind, value, source):
        value = str(value or "").strip()
        if kind == "URL" and not _is_network_url(value):
            return
        if kind == "Domain" and not _is_high_confidence_domain(value):
            return
        if kind == "IP address":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return
        key = (kind, value.lower())
        if value and key not in seen:
            entries.append({"kind": kind, "value": value, "source": source})
            seen.add(key)

    for name, value in report.get("hashes", {}).items():
        add(name.upper(), value, "Static analysis")
    for kind, values in (("URL", report.get("iocs", {}).get("urls", [])), ("Domain", report.get("iocs", {}).get("domains", [])), ("IP address", report.get("iocs", {}).get("ips", []))):
        for value in values:
            add(kind, value, "Static analysis")
    for item in report.get("dynamic", {}).get("network_requests", []):
        add(item.get("kind", "Network indicator"), item.get("value", ""), "Dynamic sandbox")
    return entries


def register_file_scan_routes(app, database, db, current_user, login_required, upload_dir):
    upload_dir = Path(upload_dir)
    active_dynamic_polls, dynamic_poll_lock = set(), threading.Lock()

    def attach_local_heuristic(task_id, report):
        if not report:
            return report
        try:
            report["local_heuristic"] = ingest_local_intelligence(database, task_id, "file_scan", report)
        except (sqlite3.Error, OSError):
            pass
        return report

    def resume_dynamic_poll(task_id):
        with dynamic_poll_lock:
            if task_id in active_dynamic_polls:
                return
            active_dynamic_polls.add(task_id)
        try:
            for _ in range(MAX_DYNAMIC_POLL_ATTEMPTS):
                time.sleep(DYNAMIC_POLL_INTERVAL)
                with sqlite3.connect(database) as connection:
                    row = connection.execute("SELECT result FROM file_scan_tasks WHERE id = ? AND status = 'Running'", (task_id,)).fetchone()
                    if not row or not row[0]:
                        return
                    report = json.loads(row[0])
                    dynamic = report.get("dynamic", {})
                    if not _stored_dynamic_is_pending(dynamic):
                        return
                    dynamic["state"] = "Queued"
                    report["dynamic"] = _refresh_dynamic_sandbox(dynamic)
                    attach_local_heuristic(task_id, report)
                    if report["dynamic"].get("state") == "Queued":
                        connection.execute("UPDATE file_scan_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
                        continue
                    status = "Failed" if report["dynamic"].get("state") in {"Unavailable", "Not configured"} else "Complete"
                    connection.execute("UPDATE file_scan_tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?", (status, json.dumps(report), datetime.now(timezone.utc).isoformat(), task_id))
                    return
        finally:
            with dynamic_poll_lock:
                active_dynamic_polls.discard(task_id)

    def worker(task_id, path, filename, provider, analysis_mode, file_password=""):
        def persist(status, report=None, error=None):
            completed_at = datetime.now(timezone.utc).isoformat() if status != "Running" else None
            attach_local_heuristic(task_id, report)
            with sqlite3.connect(database) as connection:
                connection.execute("UPDATE file_scan_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?", (status, json.dumps(report) if report else None, error, completed_at, task_id))

        try:
            report = run_file_scan(path, filename, provider, analysis_mode, file_password)
            if analysis_mode == "dynamic":
                report["dynamic"] = _submit_dynamic_sandbox(provider, path, filename, file_password, report["hashes"]["sha256"])
                report["dynamic"]["static_assessment"] = _static_triage_assessment(report)
                if report["dynamic"]["state"] == "Queued":
                    persist("Running", report)
                    for _ in range(MAX_DYNAMIC_POLL_ATTEMPTS):
                        time.sleep(DYNAMIC_POLL_INTERVAL)
                        report["dynamic"] = _refresh_dynamic_sandbox(report["dynamic"])
                        if report["dynamic"]["state"] == "Queued":
                            persist("Running", report)
                            continue
                        status = "Failed" if report["dynamic"]["state"] in {"Unavailable", "Not configured"} else "Complete"
                        persist(status, report)
                        return
                    report["dynamic"] = {**report["dynamic"], "state": "Unavailable", "detail": f"The provider did not finish within {MAX_DYNAMIC_POLL_ATTEMPTS * DYNAMIC_POLL_INTERVAL // 60} minutes. Reopen this task to resume polling."}
                    persist("Failed", report)
                    return
                status = "Failed" if report["dynamic"]["state"] in {"Unavailable", "Not configured"} else "Complete"
            else:
                status = "Complete"
            persist(status, report)
        except Exception as exc:
            persist("Failed", error=str(exc)[:1000])

    @app.route("/analysis/file", methods=["GET", "POST"])
    @login_required
    def file_scan():
        if request.method == "POST":
            upload = request.files.get("file")
            filename = secure_filename(upload.filename) if upload and upload.filename else ""
            provider = request.form.get("provider", "local")
            analysis_mode = request.form.get("analysis_mode", "static")
            file_password = request.form.get("file_password", "")
            password_declared = request.form.get("file_is_protected") == "1"
            if not filename:
                flash("Select a file to inspect.", "error")
            elif provider not in FILE_ENGINES or analysis_mode not in {"static", "dynamic"}:
                flash("Select a supported analysis engine.", "error")
            elif analysis_mode == "dynamic" and provider not in PROVIDER_ENGINES:
                flash("Dynamic analysis requires Hybrid Analysis or Filescan.io.", "error")
            elif password_declared and not file_password:
                flash("Enter the archive password to continue.", "error")
                return redirect(url_for("file_scan", password_required="1"))
            elif _zip_password_required(upload.stream) and not file_password:
                flash("This archive is password protected. Re-select it and provide the archive password to continue.", "error")
                return redirect(url_for("file_scan", password_required="1"))
            elif _zip_password_required(upload.stream) and not _valid_zip_password(upload.stream, file_password):
                flash("The archive password could not decrypt the uploaded file. Try again.", "error")
                return redirect(url_for("file_scan", password_required="1"))
            else:
                upload_dir.mkdir(parents=True, exist_ok=True)
                task_id = str(uuid.uuid4())
                stored = upload_dir / f"{task_id}_{filename}"
                upload.save(stored)
                protect_upload(stored)
                db().execute("INSERT INTO file_scan_tasks (id, user_id, filename, stored_path, engine, analysis_mode, status, result, error, created_at, completed_at, is_private) VALUES (?, ?, ?, ?, ?, ?, 'Running', NULL, NULL, ?, NULL, ?)", (task_id, current_user()["id"], filename, str(stored), provider, analysis_mode, datetime.now(timezone.utc).isoformat(), is_private_task(request.form)))
                db().commit()
                threading.Thread(target=worker, args=(task_id, str(stored), filename, provider, analysis_mode, file_password), daemon=True).start()
                flash("File analysis started. The local inspector never executes the file.", "success")
                return redirect(url_for("file_scan"))
        return render_template("file_scan.html", history=module_history(db(), "file_scan", current_user()["id"], request.args), engines=FILE_ENGINES, providers=PROVIDER_ENGINES, password_required=request.args.get("password_required") == "1")

    @app.get("/analysis/file/<task_id>")
    @login_required
    def view_file_scan(task_id):
        task = visible_task(db(), "file_scan_tasks", task_id, current_user()["id"])
        if not task:
            flash("File scan task not found.", "error")
            return redirect(url_for("file_scan"))
        report = json.loads(task["result"]) if task["result"] else None
        if report and report.get("dynamic", {}).get("provider_key") == "hybrid_analysis":
            dynamic = report["dynamic"]
            dynamic.setdefault("sample_sha256", report.get("hashes", {}).get("sha256", ""))
            if not dynamic.get("environment_id"):
                profile = _sandbox_profile(task["stored_path"], task["filename"])
                dynamic["environment_id"] = profile["id"]
            if "HTTP 410" in str(dynamic.get("detail", "")):
                dynamic["state"] = "Queued"
                dynamic["detail"] = "Retrying Hybrid Analysis with the canonical sample report identifier."
                db().execute("UPDATE file_scan_tasks SET status = 'Running', result = ?, error = NULL, completed_at = NULL WHERE id = ?", (json.dumps(report), task_id))
                db().commit()
                task = dict(task)
                task["status"] = "Running"
                threading.Thread(target=resume_dynamic_poll, args=(task_id,), daemon=True).start()
        if report and report.get("hash_reputation", {}).get("detail") == "VirusTotal returned HTTP 404.":
            report["hash_reputation"] = {"state": "Complete", "verdict": "Unknown", "detail": "VirusTotal has no prior record for this file hash.", "malicious": 0, "suspicious": 0, "clean": 0, "engines": []}
            db().execute("UPDATE file_scan_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
            db().commit()
        if report and report.get("dynamic") and task["status"] != "Running" and (_stored_dynamic_is_pending(report["dynamic"]) or _dynamic_timed_out(report["dynamic"])):
            report["dynamic"]["state"] = "Queued"
            report["dynamic"]["poll_attempts"] = 0
            report["dynamic"]["detail"] = f"{report['dynamic'].get('provider', 'The provider')} is still processing the submitted file. Polling resumed."
            db().execute("UPDATE file_scan_tasks SET status = 'Running', result = ?, completed_at = NULL WHERE id = ?", (json.dumps(report), task_id))
            db().commit()
            task = dict(task)
            task["status"] = "Running"
            threading.Thread(target=resume_dynamic_poll, args=(task_id,), daemon=True).start()
        if report and report.get("dynamic"):
            report["dynamic"]["threat_indicators"] = [
                indicator for indicator in report["dynamic"].get("threat_indicators", [])
                if indicator.get("label") != "MITRE technique"
            ]
            report["dynamic"]["fields"] = _apply_dynamic_field_tones(report["dynamic"].get("fields", []))
            actions, actions_changed = _normalise_dynamic_actions(report["dynamic"].get("actions", []))
            report["dynamic"]["actions"] = actions
            static_assessment = report["dynamic"].get("static_assessment") or _static_triage_assessment(report)
            report["dynamic"]["static_assessment"] = static_assessment
            if "ai_threat_indicators" not in report["dynamic"] or "ai_summary" not in report["dynamic"] or report["dynamic"].get("ai_summary", {}).get("style") != "soc-narrative-v2" or "recommendations" not in report["dynamic"].get("ai_summary", {}) or actions_changed or report["dynamic"].get("ai_static_verdict") != static_assessment.get("verdict", "Unknown"):
                report["dynamic"]["ai_summary"] = create_file_sandbox_summary(
                    static_assessment, report["dynamic"].get("verdict", "Unknown"), actions
                )
                time.sleep(1.5)
                report["dynamic"]["ai_threat_indicators"] = create_file_action_threat_indicators(
                    actions, report["dynamic"].get("verdict", "Unknown"), static_assessment
                )
                report["dynamic"]["ai_static_verdict"] = static_assessment.get("verdict", "Unknown")
                db().execute("UPDATE file_scan_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
                db().commit()
            if "network_connections" not in report["dynamic"]:
                report["dynamic"]["network_connections"] = _dynamic_network_connections(report["dynamic"].get("network_requests", []))
                db().execute("UPDATE file_scan_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
                db().commit()
        if task["status"] == "Running" and report and report.get("dynamic", {}).get("state") == "Queued":
            report["dynamic"] = _refresh_dynamic_sandbox(report["dynamic"])
            completed = report["dynamic"]["state"] != "Queued"
            if completed:
                status = "Failed" if report["dynamic"]["state"] in {"Unavailable", "Not configured"} else "Complete"
                db().execute("UPDATE file_scan_tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?", (status, json.dumps(report), datetime.now(timezone.utc).isoformat(), task_id))
            else:
                db().execute("UPDATE file_scan_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
            db().commit()
            task = dict(task)
            if completed:
                task["status"] = "Failed" if report["dynamic"]["state"] in {"Unavailable", "Not configured"} else "Complete"
        return render_template("file_scan_task.html", task=task, report=report, ioc_indicators=_file_ioc_indicators(report) if report else [])

    @app.post("/analysis/file/<task_id>/delete")
    @login_required
    def delete_file_scan(task_id):
        task = visible_task(db(), "file_scan_tasks", task_id, current_user()["id"])
        deleted = delete_owned_task(db(), "file_scan_tasks", task_id, current_user()["id"])
        db().commit()
        if deleted.rowcount and task:
            Path(task["stored_path"]).unlink(missing_ok=True)
            flash("File scan deleted.", "success")
        return redirect(url_for("file_scan"))

    @app.get("/analysis/file/<task_id>/export-iocs")
    @login_required
    def export_file_scan_iocs(task_id):
        task = visible_task(db(), "file_scan_tasks", task_id, current_user()["id"])
        if not task or not task["result"]:
            flash("File scan task not found.", "error")
            return redirect(url_for("file_scan"))
        report = json.loads(task["result"])
        response = jsonify({
            "task_id": task["id"], "filename": task["filename"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "indicators": _file_ioc_indicators(report),
        })
        response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-iocs-{task_id[:8]}.json"
        return response

    @app.get("/analysis/file/<task_id>/export/<export_format>")
    @login_required
    def export_file_scan_task(task_id, export_format):
        task = visible_task(db(), "file_scan_tasks", task_id, current_user()["id"])
        if not task or not task["result"]:
            flash("File scan task not found.", "error")
            return redirect(url_for("file_scan"))
        report = json.loads(task["result"])
        export_task = {key: task[key] for key in ("id", "filename", "engine", "analysis_mode", "status", "created_at", "completed_at", "is_private")}
        export_data = {"task": export_task, "report": report, "indicators_of_compromise": _file_ioc_indicators(report)}
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if export_format == "json":
            response = jsonify(export_data)
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-file-scan-{timestamp}.json"
            return response
        if export_format == "html":
            response = app.make_response(render_template("file_scan_export.html", task=export_task, report=report, ioc_indicators=export_data["indicators_of_compromise"], generated_at=datetime.now(timezone.utc)))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-file-scan-{timestamp}.html"
            return response
        flash("Unsupported export format.", "error")
        return redirect(url_for("view_file_scan", task_id=task_id))
