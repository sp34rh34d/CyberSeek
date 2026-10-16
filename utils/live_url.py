import json
import http.client
import ipaddress
import re
import socket
import sqlite3
import threading
import uuid
from base64 import urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPHandler, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from flask import flash, jsonify, make_response, redirect, render_template, request, send_from_directory, url_for

from utils.local_heuristics import ingest_local_intelligence
from utils.dns import geolocate_result
from utils.source_config import source_api_settings
from utils.soc_summary import create_live_url_ai_verdict
from utils.task_access import delete_owned_task, is_private_task, module_history, visible_task
from utils.whois import RdapNotFoundError, fetch_rdap, format_whois_output


MAX_DOCUMENT_BYTES = 1_000_000
MAX_ITEMS = 100
USER_AGENTS = {
    "firefox": {"label": "Firefox", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"},
    "chrome": {"label": "Chrome", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
    "edge": {"label": "Microsoft Edge", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"},
    "safari": {"label": "Safari", "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"},
}
SECURITY_HEADER_NAMES = (
    "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy",
    "Access-Control-Allow-Origin",
)


def _public_url_endpoint(value):
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public HTTP/HTTPS URLs are allowed for live analysis.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("The URL contains an invalid network port.") from exc
    try:
        answers = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("The URL hostname could not be resolved.") from exc
    addresses = []
    for answer in answers:
        try:
            address = ipaddress.ip_address(answer[4][0])
        except ValueError:
            continue
        if not address.is_global:
            raise ValueError("Private, local, reserved, and non-public destinations are blocked.")
        rendered = str(address)
        if rendered not in addresses:
            addresses.append(rendered)
    if not addresses:
        raise ValueError("The URL hostname did not resolve to a public address.")
    address = next((candidate for candidate in addresses if ":" not in candidate), addresses[0])
    return {"hostname": parsed.hostname.lower(), "address": address, "port": port}


def _is_public_url(value):
    try:
        _public_url_endpoint(value)
    except ValueError:
        return False
    return True


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, address, **kwargs):
        super().__init__(host, **kwargs)
        self._address = address

    def connect(self):
        if self._tunnel_host:
            raise OSError("Proxy tunnelling is disabled for live URL analysis.")
        self.sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, **kwargs):
        super().__init__(host, **kwargs)
        self._address = address

    def connect(self):
        if self._tunnel_host:
            raise OSError("Proxy tunnelling is disabled for live URL analysis.")
        connection = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(connection, server_hostname=self.host)


class _PinnedHTTPHandler(HTTPHandler):
    def http_open(self, request):
        endpoint = _public_url_endpoint(request.full_url)
        return self.do_open(lambda host, **kwargs: _PinnedHTTPConnection(host, endpoint["address"], **kwargs), request)


class _PinnedHTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        endpoint = _public_url_endpoint(request.full_url)
        return self.do_open(lambda host, **kwargs: _PinnedHTTPSConnection(host, endpoint["address"], **kwargs), request)


class _SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        if not _is_public_url(newurl):
            raise ValueError("Redirect to a private, local, or unsupported URL was blocked.")
        return super().redirect_request(request, fp, code, message, headers, newurl)


def _pinned_opener():
    return build_opener(ProxyHandler({}), _SafeRedirect(), _PinnedHTTPHandler(), _PinnedHTTPSHandler())


class _DocumentInspector(HTMLParser):
    resource_attributes = {
        "script": ("src", "script"), "img": ("src", "image"), "iframe": ("src", "frame"),
        "link": ("href", "stylesheet"), "audio": ("src", "media"), "video": ("src", "media"),
        "source": ("src", "media"), "embed": ("src", "embed"), "object": ("data", "object"),
    }

    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title, self.resources, self.activities = "", [], []
        self.password_inputs, self.download_links, self.script_patterns = 0, 0, set()
        self._in_title = False
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title":
            self._in_title = True
        if tag == "script":
            self._in_script = True
        if tag == "form":
            method = values.get("method", "GET").upper()
            action = urljoin(self.base_url, values.get("action", self.base_url))
            self.activities.append({"type": "Form", "detail": f"{method} form targets {action}"})
        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            self.activities.append({"type": "Redirect hint", "detail": values.get("content", "Meta refresh")[:240]})
        if tag == "script" and not values.get("src"):
            self.activities.append({"type": "Inline script", "detail": "Inline JavaScript is present."})
        if tag == "input" and values.get("type", "text").lower() == "password":
            self.password_inputs += 1
        if tag == "a" and re.search(r"\.(?:exe|msi|dmg|pkg|apk|jar|zip)(?:$|[?#])", values.get("href", ""), re.IGNORECASE):
            self.download_links += 1
            self.activities.append({"type": "Download link", "detail": urljoin(self.base_url, values["href"])[:300]})
        attribute = self.resource_attributes.get(tag)
        if attribute and values.get(attribute[0]):
            self.add_resource(urljoin(self.base_url, values[attribute[0]]), attribute[1])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = data.strip()[:180]
        if self._in_script:
            patterns = {
                "eval()": r"\beval\s*\(", "base64 decoding": r"\batob\s*\(",
                "character decoding": r"fromCharCode\s*\(", "document.write": r"document\.write\s*\(",
            }
            self.script_patterns.update(label for label, expression in patterns.items() if re.search(expression, data, re.IGNORECASE))

    def add_resource(self, value, kind):
        if len(self.resources) >= MAX_ITEMS or not value.startswith(("http://", "https://")):
            return
        if value not in {item["url"] for item in self.resources}:
            self.resources.append({"type": kind.title(), "url": value})


def _fetch_document(target, user_agent):
    if not _is_public_url(target):
        raise ValueError("Only public HTTP/HTTPS URLs are allowed for live analysis.")
    opener = _pinned_opener()
    request = Request(target, headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml"})
    try:
        with opener.open(request, timeout=12) as response:
            document = response.read(MAX_DOCUMENT_BYTES).decode("utf-8", "replace")
            return {
                "url": response.geturl(), "status": response.status,
                "content_type": response.headers.get_content_type(), "server": response.headers.get("Server", "Unavailable"),
                "content_length": response.headers.get("Content-Length", "Unavailable"),
                "headers": {name: response.headers.get(name) for name in SECURITY_HEADER_NAMES}, "document": document,
            }
    except HTTPError as exc:
        raise ValueError(f"HTTP {exc.code} returned by the target.") from exc
    except (URLError, TimeoutError) as exc:
        reason = exc.reason if isinstance(exc, URLError) else "request timed out"
        raise ValueError(f"Target could not be fetched: {reason}") from exc


def _browser_capture(target, output_path, user_agent, declared_resources=()):
                                                                                      
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"engine": "Playwright Chromium", "state": "Unavailable", "detail": "Install the optional Playwright browser engine to enable isolated visual capture.", "resources": [], "activities": []}

    resources, activities, seen = [], [], set()
    try:
        permitted_hosts = {}
        for value in [target, *(item.get("url", "") for item in declared_resources)]:
            try:
                endpoint = _public_url_endpoint(value)
            except ValueError:
                continue
            permitted_hosts.setdefault(endpoint["hostname"], endpoint["address"])
        target_endpoint = _public_url_endpoint(target)
        if target_endpoint["hostname"] not in permitted_hosts:
            permitted_hosts[target_endpoint["hostname"]] = target_endpoint["address"]
        resolver_rules = ", ".join(f"MAP {host} {address}" for host, address in permitted_hosts.items())
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=["--no-proxy-server", f"--host-resolver-rules={resolver_rules}"])
            context = browser.new_context(viewport={"width": 1440, "height": 900}, user_agent=user_agent, java_script_enabled=True, service_workers="block")
            page = context.new_page()

            def route_request(route):
                parsed = urlparse(route.request.url)
                if parsed.scheme in {"http", "https"} and parsed.hostname and parsed.hostname.lower() in permitted_hosts:
                    route.continue_()
                else:
                    activities.append({"type": "Blocked request", "detail": route.request.url[:300]})
                    route.abort()

            def response_received(response):
                resource_url = response.url
                if resource_url.startswith(("http://", "https://")) and resource_url not in seen and len(resources) < MAX_ITEMS:
                    seen.add(resource_url)
                    resources.append({"type": response.request.resource_type.title(), "url": resource_url, "status": response.status})

            page.route("**/*", route_request)
            page.on("response", response_received)
            page.on("console", lambda message: activities.append({"type": f"Console {message.type}", "detail": message.text[:300]}) if len(activities) < MAX_ITEMS else None)
            response = page.goto(target, wait_until="domcontentloaded", timeout=15_000)
            page.wait_for_timeout(1_500)
            page.screenshot(path=str(output_path), full_page=True)
            activities.insert(0, {"type": "Navigation", "detail": f"{response.status if response else 'Unknown'} response rendered at {page.url}"})
            context.close()
            browser.close()
        return {"engine": "Playwright Chromium", "state": "Complete", "detail": "Visual capture and browser network activity collected in an isolated browser context.", "resources": resources, "activities": activities}
    except Exception as exc:
        output_path.unlink(missing_ok=True)
        detail = str(exc)
        if "Executable doesn't exist" in detail:
            detail = "Chromium is not installed for the Cyberseek service. Run the Cyberseek installer again to provision the browser engine."
        else:
            detail = f"Browser capture is unavailable: {detail[:220]}"
        return {"engine": "Playwright Chromium", "state": "Unavailable", "detail": detail, "resources": [], "activities": activities}


def assess_live_url(target, final_url, inspector):
                                                                               
    signals, mitre = [], []
    parsed = urlparse(final_url)
    target_text = f"{target} {final_url}".lower()
    lure_terms = r"(?:login|signin|verify|account|update|invoice|payment|password|wallet|crypto)"
    if re.search(lure_terms, target_text):
        signals.append("The URL contains terms commonly used in credential or payment lures.")
        mitre.append(("T1566.002", "Phishing: Spearphishing Link"))
    if "@" in parsed.netloc or parsed.hostname.count("-") >= 3 or parsed.hostname.startswith("xn--"):
        signals.append("The host uses an unusual URL or domain structure.")
    try:
        if ipaddress.ip_address(parsed.hostname).is_global:
            signals.append("The site is addressed directly by a public IP instead of a domain name.")
    except ValueError:
        pass
    if parsed.scheme == "http":
        signals.append("The page is served over unencrypted HTTP.")
        mitre.append(("T1071.001", "Application Layer Protocol: Web Protocols"))
    if inspector.password_inputs:
        signals.append(f"Observed {inspector.password_inputs} password input field(s), indicating credential collection capability.")
        mitre.append(("T1056.003", "Input Capture: Web Portal Capture"))
    if inspector.download_links:
        signals.append(f"Observed {inspector.download_links} executable or archive download link(s).")
        mitre.append(("T1204.002", "User Execution: Malicious File"))
    if inspector.script_patterns:
        signals.append("Inline JavaScript includes potentially obfuscated or dynamic execution patterns: " + ", ".join(sorted(inspector.script_patterns)) + ".")
        mitre.extend((("T1027", "Obfuscated Files or Information"), ("T1059.007", "Command and Scripting Interpreter: JavaScript")))
    if len(inspector.resources) >= 40:
        signals.append(f"The document declares a high number of external resources ({len(inspector.resources)}).")
        mitre.append(("T1189", "Drive-by Compromise"))
    if len(signals) >= 4 or (inspector.password_inputs and inspector.script_patterns):
        verdict, confidence = "Malicious", "High"
    elif len(signals) >= 2:
        verdict, confidence = "Suspicious", "Medium"
    elif signals:
        verdict, confidence = "Suspicious", "Low"
    else:
        verdict, confidence = "Clean", "Low"
    summary = (
        "Multiple high-risk web indicators were observed. Contain and validate this URL before allowing access."
        if verdict == "Malicious" else
        "Observed signals warrant additional reputation and telemetry validation." if verdict == "Suspicious" else
        "No high-risk patterns were observed in the fetched document. This is not a guarantee of safety."
    )
    deduplicated = []
    seen = set()
    for technique in mitre:
        if technique[0] not in seen:
            seen.add(technique[0])
            deduplicated.append({"id": technique[0], "name": technique[1]})
    return {"verdict": verdict, "confidence": confidence, "summary": summary, "signals": signals, "mitre": deduplicated}


def assess_security_headers(headers, final_url):
    items = [{"name": name, "value": headers.get(name) or "Missing", "state": "Present" if headers.get(name) else "Missing"} for name in SECURITY_HEADER_NAMES]
    findings = []
    values = {name.lower(): "" for name in SECURITY_HEADER_NAMES}
    values.update({name.lower(): str(value or "") for name, value in headers.items()})
    csp = values["content-security-policy"].lower()
    if not csp:
        findings.append({"severity": "Warning", "header": "Content-Security-Policy", "detail": "Missing; the browser has no declared content execution policy."})
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        findings.append({"severity": "Warning", "header": "Content-Security-Policy", "detail": "Allows unsafe inline or evaluated script execution."})
    if urlparse(final_url).scheme == "https" and not values["strict-transport-security"]:
        findings.append({"severity": "Warning", "header": "Strict-Transport-Security", "detail": "Missing on an HTTPS response; downgrade protection is not declared."})
    if values["x-content-type-options"].lower() != "nosniff":
        findings.append({"severity": "Warning", "header": "X-Content-Type-Options", "detail": "Missing or not set to nosniff."})
    if not values["x-frame-options"] and "frame-ancestors" not in csp:
        findings.append({"severity": "Warning", "header": "X-Frame-Options", "detail": "Missing and no CSP frame-ancestors directive was observed."})
    if not values["referrer-policy"]:
        findings.append({"severity": "Info", "header": "Referrer-Policy", "detail": "Missing; browser default referrer behavior is used."})
    if values["access-control-allow-origin"].strip() == "*":
        findings.append({"severity": "Warning", "header": "Access-Control-Allow-Origin", "detail": "Wildcard cross-origin access is allowed."})
    return {"headers": items, "findings": findings}


def _domain_registration(hostname):
    try:
        ipaddress.ip_address(hostname)
        return {"state": "Not applicable", "detail": "RDAP registration dates apply to domains, not IP addresses.", "fields": []}
    except ValueError:
        pass
    try:
        fields = dict(format_whois_output(json.dumps(fetch_rdap(hostname))))
        preferred = ("Name", "Registrar", "Created", "Expires", "Last changed", "Status", "Country", "Nameservers")
        return {"state": "Complete", "detail": "RDAP registration data collected.", "fields": [{"name": name, "value": fields[name]} for name in preferred if fields.get(name)]}
    except RdapNotFoundError as exc:
        return {"state": "Not found", "detail": str(exc), "fields": []}
    except (HTTPError, URLError, ValueError, TimeoutError, RuntimeError) as exc:
        return {"state": "Unavailable", "detail": f"RDAP registration data could not be collected: {str(exc)[:180]}", "fields": []}


def _network_information(hostname):
    location = geolocate_result("", hostname)
    if not location:
        return {"state": "Unavailable", "detail": "No public IP geolocation was returned for this host."}
    return {"state": "Complete", "detail": "Public network location collected.", **location}


def _virustotal_url_reputation(target):
    key = source_api_settings().get("virustotal_api_key", "").strip()
    if not key:
        return {"state": "Not configured", "detail": "Configure a VirusTotal API key in Source APIs to collect this reputation verdict."}
    url_id = urlsafe_b64encode(target.encode()).decode().rstrip("=")
    try:
        request = Request(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key, "Accept": "application/json"})
        with build_opener().open(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        if not stats:
            return {"state": "Unavailable", "detail": "VirusTotal has no completed cached verdict for this URL."}
        malicious, suspicious, clean = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)), int(stats.get("harmless", 0))
        verdict = "Malicious" if malicious else "Suspicious" if suspicious else "Clean"
        return {"state": "Complete", "detail": "Cached VirusTotal URL reputation collected.", "verdict": verdict, "malicious": malicious, "suspicious": suspicious, "clean": clean, "unknown": sum(int(stats.get(name, 0)) for name in ("undetected", "timeout", "failure", "type-unsupported"))}
    except HTTPError as exc:
        return {"state": "Unavailable", "detail": f"VirusTotal returned HTTP {exc.code}."}
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"state": "Unavailable", "detail": f"VirusTotal reputation could not be collected: {str(exc)[:180]}"}


def _collect_enrichment(hostname, target):
    executor = ThreadPoolExecutor(max_workers=3)
    registration_future = executor.submit(_domain_registration, hostname)
    network_future = executor.submit(_network_information, hostname)
    virustotal_future = executor.submit(_virustotal_url_reputation, target)

    def enrichment(future, fallback):
        try:
            return future.result(timeout=3)
        except Exception:
            return fallback

    registration = enrichment(registration_future, {"state": "Unavailable", "detail": "RDAP registration lookup exceeded the collection window.", "fields": []})
    network = enrichment(network_future, {"state": "Unavailable", "detail": "Network lookup exceeded the collection window."})
    virustotal = enrichment(virustotal_future, {"state": "Unavailable", "detail": "VirusTotal lookup exceeded the collection window."})
    executor.shutdown(wait=False, cancel_futures=True)
    return registration, network, virustotal


def live_url_iocs(report, task):
    iocs, seen = [], set()

    def add(value, indicator_type, source):
        value = str(value or "").strip()
        identity = (indicator_type, value.lower())
        if not value or identity in seen:
            return
        seen.add(identity)
        iocs.append({"value": value, "type": indicator_type, "source": source})

    for value in (report.get("target"), report.get("final_url")):
        add(value, "url", "Live URL Analysis")
        host = urlparse(value or "").hostname
        if not host:
            continue
        try:
            add(host, "ip", "Live URL Analysis") if ipaddress.ip_address(host).is_global else None
        except ValueError:
            add(host, "domain", "Live URL Analysis")
    network_ip = report.get("network", {}).get("ip")
    if network_ip:
        add(network_ip, "ip", "Network information")
    for resource in report.get("resources", []):
        host = urlparse(resource.get("url", "")).hostname
        if not host:
            continue
        try:
            add(host, "ip", "Observed resource") if ipaddress.ip_address(host).is_global else None
        except ValueError:
            add(host, "domain", "Observed resource")
    return {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(), "task": {"id": task["id"], "target": task["target"], "status": task["status"]}, "iocs": iocs}


def refresh_live_url_ai_verdict(report):
    verdict = report.get("ai_verdict") if isinstance(report, dict) else None
    required = {"behavior", "recommendations", "limitations"}
    if isinstance(verdict, dict) and required.issubset(verdict):
        return False
    report["ai_verdict"] = create_live_url_ai_verdict(report)
    return True


def run_live_url_analysis(target, screenshot_path, user_agent_key="firefox"):
    user_agent_key = user_agent_key if user_agent_key in USER_AGENTS else "firefox"
    user_agent = USER_AGENTS[user_agent_key]["value"]
    try:
        fetched = _fetch_document(target, user_agent)
    except ValueError as exc:
        hostname = urlparse(target).hostname
        inspector = _DocumentInspector(target)
        assessment = assess_live_url(target, target, inspector)
        assessment.update({"verdict": "Unknown", "confidence": "Low", "summary": "The public URL passed input validation but could not be resolved or fetched. No rendered-content verdict is available."})
        registration, network, virustotal = _collect_enrichment(hostname, target)
        report = {
            "target": target, "user_agent": USER_AGENTS[user_agent_key]["label"], "final_url": target, "title": "Public target unavailable",
            "http": {"status": "Unavailable", "content_type": "Unavailable", "server": "Unavailable", "content_length": "Unavailable"},
            "engines": [{"engine": "HTTP Document Inspector", "state": "Unavailable", "detail": str(exc)[:260]}, {"engine": "Playwright Chromium", "state": "Unavailable", "detail": "Browser rendering was not attempted because the initial public URL could not be fetched."}],
            "resources": [], "activities": [{"type": "Network", "detail": str(exc)[:300]}],
            "assessment": assessment, "security_headers": {"headers": [], "findings": [{"severity": "Info", "header": "HTTP response", "detail": "Security headers are unavailable because no response was received."}]}, "registration": registration, "network": network, "virustotal": virustotal,
            "screenshot_available": False,
        }
        refresh_live_url_ai_verdict(report)
        return report
    inspector = _DocumentInspector(fetched["url"])
    inspector.feed(fetched["document"])
    hostname = urlparse(fetched["url"]).hostname
    enrichment_executor = ThreadPoolExecutor(max_workers=3)
    registration_future = enrichment_executor.submit(_domain_registration, hostname)
    network_future = enrichment_executor.submit(_network_information, hostname)
    virustotal_future = enrichment_executor.submit(_virustotal_url_reputation, fetched["url"])
    browser = _browser_capture(fetched["url"], screenshot_path, user_agent, inspector.resources)
    resource_index = {item["url"]: item for item in inspector.resources}
    for item in browser["resources"]:
        resource_index[item["url"]] = item
    activities = [{"type": "HTTP fetch", "detail": f"HTTP {fetched['status']} · {fetched['content_type']} · {fetched['url']}"}]
    activities.extend(inspector.activities)
    activities.extend(browser["activities"])
    assessment = assess_live_url(target, fetched["url"], inspector)
    security_headers = assess_security_headers(fetched["headers"], fetched["url"])
    def enrichment(future, fallback):
        try:
            return future.result(timeout=3)
        except Exception:
            return fallback
    registration = enrichment(registration_future, {"state": "Unavailable", "detail": "RDAP registration lookup exceeded the collection window.", "fields": []})
    network = enrichment(network_future, {"state": "Unavailable", "detail": "Network lookup exceeded the collection window."})
    virustotal = enrichment(virustotal_future, {"state": "Unavailable", "detail": "VirusTotal lookup exceeded the collection window."})
    enrichment_executor.shutdown(wait=False, cancel_futures=True)
    report = {
        "target": target, "user_agent": USER_AGENTS[user_agent_key]["label"], "final_url": fetched["url"], "title": inspector.title or "Untitled document",
        "http": {key: fetched[key] for key in ("status", "content_type", "server", "content_length")},
        "engines": [{"engine": "HTTP Document Inspector", "state": "Complete", "detail": "Fetched the public document and extracted declared resources and interaction points."}, {key: browser[key] for key in ("engine", "state", "detail")}],
        "resources": list(resource_index.values())[:MAX_ITEMS], "activities": activities[:MAX_ITEMS],
        "assessment": assessment, "security_headers": security_headers,
        "registration": registration, "network": network, "virustotal": virustotal,
        "screenshot_available": browser["state"] == "Complete" and screenshot_path.exists(),
    }
    refresh_live_url_ai_verdict(report)
    return report


def register_live_url_routes(app, database, db, current_user, login_required, capture_dir):
    capture_dir = Path(capture_dir)

    def worker(task_id, target, user_agent):
        screenshot_path = capture_dir / f"{task_id}.png"
        try:
            capture_dir.mkdir(parents=True, exist_ok=True)
            report = run_live_url_analysis(target, screenshot_path, user_agent)
            report["local_heuristic"] = ingest_local_intelligence(database, task_id, "live_url", report)
            result, status, error = json.dumps(report), "Complete", None
        except (OSError, ValueError) as exc:
            screenshot_path.unlink(missing_ok=True)
            result, status, error = None, "Failed", str(exc)[:1000]
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE live_url_tasks SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?", (status, result, error, datetime.now(timezone.utc).isoformat(), task_id))

    @app.route("/analysis/live-url", methods=["GET", "POST"])
    @login_required
    def live_url_analysis():
        if request.method == "POST":
            target = request.form.get("target", "").strip()
            user_agent = request.form.get("user_agent", "firefox").strip().lower()
            if not _is_public_url(target):
                flash("Enter a public HTTP/HTTPS URL. Private and local destinations are blocked.", "error")
            elif user_agent not in USER_AGENTS:
                flash("Select a supported browser user agent.", "error")
            else:
                task_id = str(uuid.uuid4())
                db().execute("INSERT INTO live_url_tasks (id, user_id, target, user_agent, status, result, error, created_at, completed_at, is_private) VALUES (?, ?, ?, ?, 'Running', NULL, NULL, ?, NULL, ?)", (task_id, current_user()["id"], target, user_agent, datetime.now(timezone.utc).isoformat(), is_private_task(request.form)))
                db().commit()
                threading.Thread(target=worker, args=(task_id, target, user_agent), daemon=True).start()
                flash("Live URL analysis started in the isolated browser profile.", "success")
                return redirect(url_for("live_url_analysis"))
        requested_target = request.args.get("target", "").strip() if request.method == "GET" else ""
        return render_template("live_url.html", history=module_history(db(), "live_url", current_user()["id"], request.args), user_agents=USER_AGENTS, requested_target=requested_target)

    @app.get("/analysis/live-url/<task_id>")
    @login_required
    def view_live_url_analysis(task_id):
        task = visible_task(db(), "live_url_tasks", task_id, current_user()["id"])
        if not task:
            flash("Live URL analysis task not found.", "error")
            return redirect(url_for("live_url_analysis"))
        report = json.loads(task["result"]) if task["result"] else None
        if report and refresh_live_url_ai_verdict(report):
            db().execute("UPDATE live_url_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
            db().commit()
        return render_template("live_url_task.html", task=task, report=report)

    @app.get("/analysis/live-url/<task_id>/screenshot")
    @login_required
    def live_url_screenshot(task_id):
        task = visible_task(db(), "live_url_tasks", task_id, current_user()["id"])
        capture = capture_dir / f"{task_id}.png"
        if not task or not capture.is_file():
            return "Screenshot not available.", 404
        return send_from_directory(capture_dir, capture.name, mimetype="image/png", as_attachment=False)

    @app.get("/analysis/live-url/<task_id>/export/<export_format>")
    @login_required
    def export_live_url_analysis(task_id, export_format):
        task = visible_task(db(), "live_url_tasks", task_id, current_user()["id"])
        if not task:
            flash("Live URL analysis task not found.", "error")
            return redirect(url_for("live_url_analysis"))
        report = json.loads(task["result"]) if task["result"] else None
        if not report:
            flash("This task has no completed report to export.", "error")
            return redirect(url_for("view_live_url_analysis", task_id=task_id))
        if refresh_live_url_ai_verdict(report):
            db().execute("UPDATE live_url_tasks SET result = ? WHERE id = ?", (json.dumps(report), task_id))
            db().commit()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if export_format == "json":
            payload = dict(task)
            payload["report"] = report
            response = make_response(jsonify(payload))
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-live-url-{timestamp}.json"
            return response
        if export_format == "html":
            response = make_response(render_template("live_url_export.html", task=task, report=report, generated_at=datetime.now(timezone.utc)))
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-live-url-{timestamp}.html"
            return response
        flash("Unsupported export format.", "error")
        return redirect(url_for("view_live_url_analysis", task_id=task_id))

    @app.get("/analysis/live-url/<task_id>/export/iocs.json")
    @login_required
    def export_live_url_iocs(task_id):
        task = visible_task(db(), "live_url_tasks", task_id, current_user()["id"])
        if not task:
            flash("Live URL analysis task not found.", "error")
            return redirect(url_for("live_url_analysis"))
        if not task["result"]:
            flash("IoCs are available once this task has a completed report.", "error")
            return redirect(url_for("view_live_url_analysis", task_id=task_id))
        response = make_response(jsonify(live_url_iocs(json.loads(task["result"]), task)))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        response.headers["Content-Disposition"] = f"attachment; filename=cyberseek-live-url-iocs-{timestamp}.json"
        return response

    @app.post("/analysis/live-url/<task_id>/delete")
    @login_required
    def delete_live_url_analysis(task_id):
        deleted = delete_owned_task(db(), "live_url_tasks", task_id, current_user()["id"])
        db().commit()
        if deleted.rowcount:
            (capture_dir / f"{task_id}.png").unlink(missing_ok=True)
            flash("Live URL analysis deleted.", "success")
        return redirect(url_for("live_url_analysis"))
