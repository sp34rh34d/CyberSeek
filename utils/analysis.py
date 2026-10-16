import ipaddress
import re
import socket
from urllib.parse import urlparse


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
