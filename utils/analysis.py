import hashlib
import ipaddress
import json
import os
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def is_private_host(hostname):
    if not hostname or hostname.lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        for address in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(address[4][0])
            if not ip.is_global:
                return True
    except socket.gaierror:
        return False
    return False


def analyze_url(value):
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "High", "The URL is not a valid HTTP/HTTPS address.", ["T1583.001"]
    signals, techniques = [], []
    if is_private_host(parsed.hostname):
        signals.append("Private or local target blocked to prevent SSRF"); techniques.append("T1190")
    if parsed.scheme == "http":
        signals.append("Uses unencrypted HTTP"); techniques.append("T1071.001")
    if re.search(r"(login|verify|update|invoice|payment|password|wallet|crypto|free|download)", value, re.IGNORECASE):
        signals.append("Contains terms frequently seen in phishing campaigns"); techniques.append("T1566.002")
    if "@" in parsed.netloc or parsed.hostname.count("-") >= 3:
        signals.append("Unusual domain structure"); techniques.append("T1583.001")
    if not signals:
        signals.append("No critical static indicators; reputation and external sandbox checks are recommended")
    risk = "High" if len(signals) >= 3 else "Medium" if len(signals) >= 2 else "Low"
    return risk, "; ".join(signals) + ".", sorted(set(techniques))


def analyze_file(filename, path, allowed_extensions):
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    size = path.stat().st_size
    signals, techniques = [f"Size: {size:,} bytes", f"Extension: .{extension or 'no extension'}"], []
    high_risk = {"exe", "dll", "js", "ps1", "apk"}
    if extension in high_risk:
        signals.append("Executable or script format: requires isolated detonation"); techniques += ["T1204.002", "T1059"]
    if extension in {"zip", "doc", "docx", "xls", "xlsx"}:
        signals.append("Archive or document that can carry active content"); techniques.append("T1204.002")
    if extension not in allowed_extensions:
        signals.append("File type is not allowed for this analysis profile"); techniques.append("T1204.002")
    risk = "High" if extension in high_risk else "Medium" if techniques else "Low"
    return risk, "; ".join(signals) + ".", sorted(set(techniques))


def notify_n8n(payload):
    webhook = os.getenv("N8N_WEBHOOK_URL", "").strip()
    if not webhook:
        return "Not configured"
    try:
        data = json.dumps(payload).encode("utf-8")
        request = Request(webhook, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=8) as response:
            return "Sent" if 200 <= response.status < 300 else f"HTTP error {response.status}"
    except (URLError, HTTPError, ValueError):
        return "Unavailable"
