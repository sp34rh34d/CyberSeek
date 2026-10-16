import json
import re
import socket
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from flask import flash, redirect, render_template, request, url_for

from utils.dns import resolves_to_non_public_ip
from utils.reputation import virustotal_domain_associations
from utils.source_config import source_api_settings
from utils.task_access import delete_owned_task, is_private_task, module_history, visible_task


DISCOVERY_SOURCES = {
    "virustotal": "VirusTotal",
    "otx": "AlienVault OTX",
    "archive": "Internet Archive",
    "shodan": "Shodan",
    "crtsh": "crt.sh",
}
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP submission",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP alternate", 8443: "HTTPS alternate", 10443: "HTTPS alternate", 9443: "HTTPS alternate",
    11443: "HTTPS alternate", 8444: "HTTPS alternate", 10444: "HTTPS alternate",
    8081: "HTTPS alternate", 88: "Kerberos", 445: "SMB", 389: "LDAP", 2222: "SSH alternate",
    2022: "SSH alternate", 1433: "MSSQL", 514: "Syslog"
}
MAX_SUBDOMAINS = 60
MAX_IPS_PER_HOST = 2
MAX_IP_TARGETS = 256
MIN_SURFACE_INTERVAL_MINUTES = 60
MAX_SURFACE_INTERVAL_MINUTES = 10080
FULL_TCP_PORT_RANGE = range(1, 10001)
FULL_TCP_SCAN_WORKERS = 24
FULL_TCP_SCAN_BATCH_SIZE = 256
FULL_TCP_SCAN_BATCH_PAUSE_SECONDS = 0.05
SCHEDULER_WAKE_SECONDS = 30
_scheduler_started = False
_scheduler_guard = threading.Lock()
_progress_guard = threading.Lock()


def _utc_now():
    return datetime.now(timezone.utc)


def _surface_interval(form):
                                                                                   
    raw_value = form.get("interval_value", form.get("interval_minutes", ""))
    unit = form.get("interval_unit", "minutes").strip().lower()
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return 0
    if value < 1 or unit not in {"minutes", "hours"}:
        return 0
    interval = value * 60 if unit == "hours" else value
    return interval if MIN_SURFACE_INTERVAL_MINUTES <= interval <= MAX_SURFACE_INTERVAL_MINUTES else 0


def _surface_poll_delta(target_type, interval_minutes):
    return timedelta(minutes=int(interval_minutes))


def _surface_interval_label(interval_minutes, target_type="domain"):
    minutes = int(interval_minutes)
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour{'s' if hours != 1 else ''}"
    if minutes < 60:
        return f"{minutes} min"
    hours, remainder = divmod(minutes, 60)
    return f"{hours} hour{'s' if hours != 1 else ''} {remainder} min"


def _surface_target_label(target_type):
    return {"domain": "DOMAIN", "ip": "IP", "cidr": "CIDR", "ip_blocks": "IP BLOCKS"}.get(target_type, str(target_type).upper())


def _valid_domain(value):
    return bool(re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value))


def _surface_target_single(value):
                                                                       
    candidate = value.strip().lower().rstrip(".")
    try:
        address = ip_address(candidate)
        return ("ip", str(address), None) if address.is_global else (None, None, "Only public IP addresses are allowed.")
    except ValueError:
        pass
    if "/" in candidate:
        try:
            network = ip_network(candidate, strict=False)
        except ValueError:
            return None, None, "Enter a valid public IP address or CIDR block."
        address_count = network.num_addresses - 2 if network.version == 4 and network.num_addresses > 2 else network.num_addresses
        if not address_count or address_count > MAX_IP_TARGETS:
            return None, None, f"CIDR blocks are limited to {MAX_IP_TARGETS} public addresses per task."
        addresses = list(network.hosts()) if network.version == 4 and network.num_addresses > 2 else list(network)
        if any(not address.is_global for address in addresses):
            return None, None, "CIDR blocks containing private, local, reserved, or non-public IP addresses are not allowed."
        return "cidr", str(network), None
    return ("domain", candidate, None) if _valid_domain(candidate) else (None, None, "Enter a valid registrable domain, public IP address, or CIDR block.")


def _surface_target(value):
                                                                       
    candidates = [item for item in re.split(r"[\s,;]+", value.strip()) if item]
    if not candidates:
        return None, None, "Enter a valid registrable domain, public IP address, or CIDR block."
    if len(candidates) == 1:
        return _surface_target_single(candidates[0])

    normalized = []
    addresses = set()
    for candidate in candidates:
        target_type, target, error = _surface_target_single(candidate)
        if error:
            return None, None, error
        if target_type == "domain":
            return None, None, "A domain must be monitored in its own task; multiple public IPs or CIDR blocks are allowed together."
        try:
            network = ip_network(target, strict=False)
            members = list(network.hosts()) if network.version == 4 and network.num_addresses > 2 else list(network)
        except ValueError:
            members = [ip_address(target)]
        addresses.update(str(address) for address in members)
        if len(addresses) > MAX_IP_TARGETS:
            return None, None, f"Combined IP and CIDR targets are limited to {MAX_IP_TARGETS} public addresses per task."
        normalized.append(target)
    return "ip_blocks", ",".join(dict.fromkeys(normalized)), None


def _public_ip(value):
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def _http_json(endpoint, headers=None, timeout=5):
    request_headers = {"Accept": "application/json", "User-Agent": "Cyberseek-Surface-Monitor/1.0"}
    request_headers.update(headers or {})
    try:
        with urlopen(Request(endpoint, headers=request_headers), timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8", "replace"))
    except HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8", "replace"))
        except (ValueError, json.JSONDecodeError, OSError):
            payload = {"error": f"HTTP {exc.code}"}
        return exc.code, payload if isinstance(payload, dict) else {"error": f"HTTP {exc.code}"}
    except Exception as exc:
        return None, {"error": str(exc)}


def _source_detail(source, status, payload, success_detail):
    if status == 200:
        return success_detail
    error = str(payload.get("error") or payload.get("message") or "").strip() if isinstance(payload, dict) else ""
    if source == "virustotal" and status == 400:
        return "The configured API key cannot access this subdomain relationship. Verify the API key and plan access."
    if "timed out" in error.lower() or "timeout" in error.lower():
        if source == "crtsh":
            return "crt.sh did not respond before its 15-second certificate-transparency timeout. It will be retried on the next scheduled probe."
        return "The provider did not respond before the timeout. It will be retried on the next scheduled probe."
    return error or f"Provider request was unavailable (HTTP {status})."


def _within_scope(hostname, domain):
    candidate = hostname.lower().rstrip(".").lstrip("*.")
    return candidate == domain or candidate.endswith("." + domain)


def _discover_virustotal(domain, _settings):
    report = virustotal_domain_associations(domain)
    entries = report.get("associations", {}).get("subdomains", [])
    names = {item.get("value", "").lower() if isinstance(item, dict) else str(item).lower() for item in entries}
    names.discard("")
    report_state = report.get("state", "Unavailable")
    state = "Complete" if report_state == "Complete" else "Not configured" if report_state == "Not configured" else "Unavailable"
    return names, {
        "name": DISCOVERY_SOURCES["virustotal"], "state": state, "count": len(names),
        "detail": report.get("summary", "VirusTotal Reputation Lookup did not return associated subdomains."),
        "url": f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}",
    }


def _discover_otx(domain, settings):
    key = settings.get("otx_api_key", "").strip()
    if not key:
        return set(), {"name": DISCOVERY_SOURCES["otx"], "state": "Not configured", "count": 0,
            "url": f"https://otx.alienvault.com/indicator/domain/{quote(domain, safe='')}"}
    status, payload = _http_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain, safe='')}/passive_dns",
        {"X-OTX-API-KEY": key},
    )
    records = payload.get("passive_dns", []) if isinstance(payload, dict) else []
    names = {str(item.get("hostname") or item.get("host") or "").lower() for item in records}
    names.discard("")
    names = {name.rstrip(".").lstrip("*.") for name in names if _within_scope(name.rstrip(".").lstrip("*."), domain)}
    state = "Complete" if status == 200 else "Unavailable"
    return names, {"name": DISCOVERY_SOURCES["otx"], "state": state, "count": len(names),
        "detail": _source_detail("otx", status, payload, "Direct passive DNS lookup."),
        "url": f"https://otx.alienvault.com/indicator/domain/{quote(domain, safe='')}"}


def _discover_archive(domain, _settings):
    endpoint = "https://web.archive.org/cdx/search/cdx?" + urlencode({
        "url": f"*.{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey", "filter": "statuscode:200",
    })
    status, payload = _http_json(endpoint)
    rows = payload[1:] if isinstance(payload, list) else []
    names = {urlparse(row[0] if isinstance(row, list) else row).hostname or "" for row in rows}
    names.discard("")
    state = "Complete" if status == 200 else "Unavailable"
    return names, {"name": DISCOVERY_SOURCES["archive"], "state": state, "count": len(names),
        "detail": _source_detail("archive", status, payload, "Historical URL hostname extraction."),
        "url": f"https://web.archive.org/web/*/https://*.{domain}/*"}


def _discover_shodan(domain, settings):
    key = settings.get("shodan_api_key", "").strip()
    if not key:
        return set(), {"name": DISCOVERY_SOURCES["shodan"], "state": "Not configured", "count": 0,
            "url": f"https://www.shodan.io/domain/{quote(domain, safe='')}"}
    endpoint = "https://api.shodan.io/dns/domain/" + quote(domain, safe="") + "?" + urlencode({"key": key})
    status, payload = _http_json(endpoint)
    names = set(payload.get("subdomains", [])) if isinstance(payload, dict) else set()
    for record in payload.get("data", []) if isinstance(payload, dict) else []:
        names.add(record.get("subdomain", ""))
    expanded = {domain if not item else f"{item.lstrip('*.')}.{domain}" for item in names}
    state = "Complete" if status == 200 else "Unavailable"
    return expanded, {"name": DISCOVERY_SOURCES["shodan"], "state": state, "count": len(expanded),
        "detail": _source_detail("shodan", status, payload, "Direct DNS dataset lookup."),
        "url": f"https://www.shodan.io/domain/{quote(domain, safe='')}"}


def _discover_crtsh(domain, _settings):
    endpoint = "https://crt.sh/?" + urlencode({"q": f"%.{domain}", "output": "json", "exclude": "expired"})
    status, payload = _http_json(endpoint, timeout=15)
    names = set()
    if isinstance(payload, list):
        for certificate in payload:
            if not isinstance(certificate, dict):
                continue
            names.update(str(certificate.get("name_value", "")).lower().splitlines())
            common_name = str(certificate.get("common_name", "")).lower()
            if common_name:
                names.add(common_name)
    names = {name.rstrip(".").lstrip("*.") for name in names if _within_scope(name.rstrip(".").lstrip("*."), domain)}
    state = "Complete" if status == 200 else "Unavailable"
    return names, {"name": DISCOVERY_SOURCES["crtsh"], "state": state, "count": len(names),
        "detail": _source_detail("crtsh", status, payload, "Certificate transparency SAN extraction."),
        "url": f"https://crt.sh/?q={quote('%.' + domain, safe='')}"}


def _discover(domain, selected_sources):
    settings = source_api_settings()
    handlers = {
        "virustotal": _discover_virustotal,
        "otx": _discover_otx,
        "archive": _discover_archive,
        "shodan": _discover_shodan,
        "crtsh": _discover_crtsh,
    }
    source_results = {}
    with ThreadPoolExecutor(max_workers=min(5, len(selected_sources) or 1)) as executor:
        futures = {executor.submit(handlers[source], domain, settings): source for source in selected_sources}
        for future in as_completed(futures):
            source = futures[future]
            try:
                source_results[source] = future.result()
            except Exception as exc:
                source_results[source] = (set(), {
                    "name": DISCOVERY_SOURCES[source], "state": "Unavailable", "count": 0,
                    "detail": f"Source request failed: {str(exc)[:160]}",
                    "url": {
                        "virustotal": f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}",
                        "otx": f"https://otx.alienvault.com/indicator/domain/{quote(domain, safe='')}",
                        "archive": f"https://web.archive.org/web/*/https://*.{domain}/*",
                        "shodan": f"https://www.shodan.io/domain/{quote(domain, safe='')}",
                        "crtsh": f"https://crt.sh/?q={quote('%.' + domain, safe='')}",
                    }[source],
                })
    discoveries, source_rows, attribution = {domain}, [], {domain: {"Root domain"}}
    for source in selected_sources:
        try:
            names, source_row = source_results[source]
        except Exception as exc:
            names = set()
            source_row = {
                "name": DISCOVERY_SOURCES[source], "state": "Unavailable", "count": 0,
                "detail": f"Source request failed: {str(exc)[:160]}",
                "url": {
                    "virustotal": f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}",
                    "otx": f"https://otx.alienvault.com/indicator/domain/{quote(domain, safe='')}",
                    "archive": f"https://web.archive.org/web/*/https://*.{domain}/*",
                    "shodan": f"https://www.shodan.io/domain/{quote(domain, safe='')}",
                    "crtsh": f"https://crt.sh/?q={quote('%.' + domain, safe='')}",
                }[source],
            }
        source_rows.append(source_row)
        for name in names:
            candidate = name.lower().rstrip(".").lstrip("*.")
            if _within_scope(candidate, domain):
                discoveries.add(candidate)
                attribution.setdefault(candidate, set()).add(source_row["name"])
    return sorted(discoveries)[:MAX_SUBDOMAINS], source_rows, attribution


def _resolve_public_ips(hostname):
    try:
        answers = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, TimeoutError):
        return []
    return sorted({answer[4][0] for answer in answers if _public_ip(answer[4][0])})[:MAX_IPS_PER_HOST]


def _open_ports(address):
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.create_connection((address, port), timeout=0.35):
                open_ports.append({"port": port, "service": service})
        except (OSError, TimeoutError):
            continue
    return open_ports


def _open_all_tcp_ports(address, progress_callback=None):
                                                                                        
    def probe(port):
        try:
            with socket.create_connection((address, port), timeout=0.2):
                return {"port": port, "service": COMMON_PORTS.get(port, "Unknown service")}
        except (OSError, TimeoutError):
            return None

    services = []
    ports = tuple(FULL_TCP_PORT_RANGE)
    with ThreadPoolExecutor(max_workers=FULL_TCP_SCAN_WORKERS) as executor:
        for start in range(0, len(ports), FULL_TCP_SCAN_BATCH_SIZE):
            batch = ports[start:start + FULL_TCP_SCAN_BATCH_SIZE]
            services.extend(service for service in executor.map(probe, batch) if service)
            if progress_callback:
                progress_callback(min(start + len(batch), len(ports)), len(ports))
            if start + FULL_TCP_SCAN_BATCH_SIZE < len(ports):
                time.sleep(FULL_TCP_SCAN_BATCH_PAUSE_SECONDS)
    return services


def _open_known_ports(address, prior_services):
                                                                               
    live = []
    for service in prior_services:
        try:
            with socket.create_connection((address, int(service["port"])), timeout=0.35):
                live.append({"ip": address, "port": int(service["port"]), "service": service.get("service") or COMMON_PORTS.get(int(service["port"]), "Unknown")})
        except (OSError, TimeoutError, ValueError, KeyError):
            continue
    return live


def _check_web_reachability(address):
                                                                                         
    for port in (443, 80):
        try:
            with socket.create_connection((address, port), timeout=0.5):
                return "HTTPS" if port == 443 else "HTTP"
        except (OSError, TimeoutError):
            continue
    return None


def _probe_host(hostname, sources, previous_item=None, full_tcp_scan=False, progress_callback=None):
    addresses = _resolve_public_ips(hostname)
    services = []
    reachability = None
    prior_ips = set(previous_item.get("ips", []) if previous_item else [])
    prior_services = previous_item.get("services", []) if previous_item else []
    prior_ips.update(service.get("ip") for service in prior_services if service.get("ip"))
    for address_index, address in enumerate(addresses):
        if full_tcp_scan:
            total_addresses = max(1, len(addresses))
            def update_address_progress(completed, total):
                if progress_callback:
                    progress_callback((address_index + (completed / total)) / total_addresses)
            for port in _open_all_tcp_ports(address, update_address_progress):
                services.append({"ip": address, **port})
            continue
        existing_services = [service for service in prior_services if service.get("ip") == address]
        if previous_item and address in prior_ips:
            known_services = _open_known_ports(address, existing_services)
            services.extend(known_services)
            if known_services:
                reachability = "Known service"
            elif not existing_services:
                reachability = reachability or _check_web_reachability(address)
        else:
            for port in _open_ports(address):
                services.append({"ip": address, **port})
    if progress_callback and not full_tcp_scan:
        progress_callback(1.0)
    return {
        "hostname": hostname,
        "alive": bool(services) or bool(reachability),
        "ips": addresses,
        "services": services,
        "sources": sorted(sources),
        "ip_changed": bool(previous_item and set(addresses) != prior_ips),
        "reachability": reachability,
    }


def _surface_ip_network_info(address):
                                                                                  
    detail = {"ip": address, "country": "Unavailable", "owner": "Unavailable", "isp": "Unavailable"}
    if not _public_ip(address):
        return {**detail, "country": "Private / non-public", "owner": "Not applicable", "isp": "Not applicable"}
    try:
        with urlopen(Request(f"https://ipwho.is/{address}", headers={"Accept": "application/json", "User-Agent": "Cyberseek-Surface-Monitor/1.0"}), timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        if not payload.get("success", True):
            return detail
        connection = payload.get("connection") or {}
        return {
            **detail,
            "country": payload.get("country") or "Unavailable",
            "owner": connection.get("org") or connection.get("isp") or "Unavailable",
            "isp": connection.get("isp") or "Unavailable",
        }
    except (HTTPError, URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError):
        return detail


def _surface_ip_network_cache(database, addresses):
                                                                                  
    if not addresses:
        return {}
    placeholders = ", ".join("?" for _ in addresses)
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            f"SELECT ip_address, country, owner, isp FROM surface_ip_cache WHERE ip_address IN ({placeholders})", addresses
        ).fetchall()
    intelligence = {
        row[0]: {"ip": row[0], "country": row[1], "owner": row[2], "isp": row[3]}
        for row in rows
    }
    uncached = [address for address in addresses if address not in intelligence]
    if not uncached:
        return intelligence
    with ThreadPoolExecutor(max_workers=min(8, len(uncached))) as executor:
        discovered = list(executor.map(_surface_ip_network_info, uncached))
    timestamp = _utc_now().isoformat()
    with sqlite3.connect(database) as connection:
        connection.executemany(
            """INSERT OR REPLACE INTO surface_ip_cache (ip_address, country, owner, isp, cached_at)
            VALUES (?, ?, ?, ?, ?)""",
            [(item["ip"], item["country"], item["owner"], item["isp"], timestamp) for item in discovered],
        )
    intelligence.update({item["ip"]: item for item in discovered})
    return intelligence


def _ip_targets(target):
    addresses = []
    for candidate in [item for item in target.split(",") if item]:
        try:
            network = ip_network(candidate, strict=False)
            members = list(network.hosts()) if network.version == 4 and network.num_addresses > 2 else list(network)
        except ValueError:
            members = [ip_address(candidate)]
        addresses.extend(members)
    hostnames = list(dict.fromkeys(str(address) for address in addresses if address.is_global))[:MAX_IP_TARGETS]
    source_rows = [{
        "name": "Direct target probe", "state": "Complete", "count": len(hostnames),
        "detail": "TCP ports 1–10000 are checked gradually for each explicit public IP target.", "url": None,
    }]
    return hostnames, source_rows, {hostname: {"Direct target"} for hostname in hostnames}


def _set_surface_progress_items(database, task_id, hostnames):
    items = [{"item": hostname, "progress": 0} for hostname in hostnames]
    try:
        with sqlite3.connect(database, timeout=1) as connection:
            connection.execute(
                "UPDATE surface_tasks SET progress_items = ? WHERE id = ? AND status = 'Running'",
                (json.dumps(items), task_id),
            )
    except sqlite3.Error:
        pass


def _update_surface_progress(database, task_id, fraction, item=None, item_fraction=None):
    progress = min(99, max(0, int(fraction * 100)))
    try:
        with _progress_guard, sqlite3.connect(database, timeout=1) as connection:
            row = connection.execute("SELECT progress_items FROM surface_tasks WHERE id = ? AND status = 'Running'", (task_id,)).fetchone()
            if not row:
                return
            try:
                items = json.loads(row[0]) if row[0] else []
            except (TypeError, ValueError, json.JSONDecodeError):
                items = []
            if item is not None and item_fraction is not None:
                item_progress = min(99, max(0, int(item_fraction * 100)))
                for entry in items:
                    if entry.get("item") == item:
                        entry["progress"] = max(int(entry.get("progress", 0)), item_progress)
                        break
            connection.execute(
                "UPDATE surface_tasks SET progress = CASE WHEN progress > ? THEN progress ELSE ? END, progress_items = ?, updated_at = ? WHERE id = ? AND status = 'Running'",
                (progress, progress, json.dumps(items), _utc_now().isoformat(), task_id),
            )
    except sqlite3.Error:
        pass


def _run_surface_probe(database, task_id):
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT domain, interval_minutes, sources, result, target_type FROM surface_tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            return
        claimed = connection.execute("UPDATE surface_tasks SET status = 'Running', error = NULL, progress = 0, progress_items = '[]' WHERE id = ? AND status IN ('Queued', 'Monitoring')", (task_id,)).rowcount
        connection.commit()
    if not claimed:
        return

    now = _utc_now()
    try:
        selected = [source for source in json.loads(row[2]) if source in DISCOVERY_SOURCES]
        try:
            previous_report = json.loads(row[3]) if row[3] else None
        except json.JSONDecodeError:
            previous_report = None
        previous_items = {
            item.get("hostname"): item for item in (previous_report or {}).get("subdomains", []) if item.get("hostname")
        }
        previous_services = {
            hostname: {(service.get("ip"), service.get("port")) for service in item.get("services", [])}
            for hostname, item in previous_items.items()
        }
        hostnames, source_rows, attribution = _discover(row[0], selected) if row[4] == "domain" else _ip_targets(row[0])
        if row[4] == "domain" and previous_items:
            known_hosts = [hostname for hostname in sorted(previous_items) if _within_scope(hostname, row[0])]
            for hostname in known_hosts:
                attribution.setdefault(hostname, set()).update(previous_items[hostname].get("sources") or {"Previous inventory"})
            hostnames = (known_hosts + [hostname for hostname in hostnames if hostname not in previous_items])[:MAX_SUBDOMAINS]
        _set_surface_progress_items(database, task_id, hostnames)
        results = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            total_hosts = max(1, len(hostnames))
            for host_index, hostname in enumerate(hostnames):
                def update_host_progress(fraction, host_index=host_index, hostname=hostname):
                    _update_surface_progress(database, task_id, (host_index + fraction) / total_hosts, hostname, fraction)
                futures[executor.submit(
                    _probe_host, hostname, attribution.get(hostname, set()), previous_items.get(hostname),
                    row[4] != "domain", update_host_progress,
                )] = hostname
            for future in as_completed(futures):
                hostname = futures[future]
                try:
                    results.append(future.result())
                except Exception:
                    results.append({
                        "hostname": hostname, "alive": False, "ips": [], "services": [],
                        "sources": sorted(attribution.get(hostname, set())),
                    })
        if previous_report:
            for item in results:
                current = {(service["ip"], service["port"]) for service in item["services"]}
                additions = current - previous_services.get(item["hostname"], set())
                item["new_services"] = [
                    service for service in item["services"] if (service["ip"], service["port"]) in additions
                ]
                item["has_new_service"] = bool(additions)
        else:
            for item in results:
                item["new_services"] = []
                item["has_new_service"] = False
        results.sort(key=lambda item: (not item["alive"], item["hostname"]))
        public_ips = sorted({address for item in results for address in item["ips"]})
        ip_network_info = _surface_ip_network_cache(database, public_ips)
        for item in results:
            item["ip_network_info"] = {address: ip_network_info.get(address, {}) for address in item["ips"]}
        open_services = sum(len(item["services"]) for item in results)
        report = {
            "domain": row[0], "target_type": row[4], "generated_at": now.isoformat(), "sources": source_rows, "subdomains": results,
            "summary": {"discovered": len(results), "alive": sum(item["alive"] for item in results),
                "inactive": sum(not item["alive"] for item in results), "public_ips": len(public_ips), "open_services": open_services},
        }
        status, error = "Monitoring", None
    except Exception as exc:
        report, status, error = None, "Monitoring", str(exc)[:1000]
    with sqlite3.connect(database) as connection:
        current = connection.execute("SELECT interval_minutes FROM surface_tasks WHERE id = ?", (task_id,)).fetchone()
        effective_interval = int(current[0]) if current else int(row[1])
        finished_at = _utc_now()
        next_poll = finished_at + _surface_poll_delta(row[4], effective_interval)
        final_progress = 100 if report else 0
        final_items = json.dumps([{"item": item["hostname"], "progress": 100} for item in results]) if report else None
        connection.execute(
            """UPDATE surface_tasks SET status = CASE WHEN status = 'Paused' THEN 'Paused' ELSE ? END,
                result = COALESCE(?, result), error = ?, progress = ?, progress_items = COALESCE(?, progress_items), last_run_at = ?,
                next_run_at = CASE WHEN status = 'Paused' THEN next_run_at ELSE ? END, updated_at = ? WHERE id = ?""",
            (status, json.dumps(report) if report else None, error, final_progress, final_items, finished_at.isoformat(), next_poll.isoformat(), finished_at.isoformat(), task_id),
        )


def _surface_scheduler(database):
    while True:
        now = _utc_now().isoformat()
        try:
            with sqlite3.connect(database) as connection:
                task_ids = [row[0] for row in connection.execute(
                    "SELECT id FROM surface_tasks WHERE next_run_at <= ? AND status = 'Monitoring'", (now,)
                ).fetchall()]
            for task_id in task_ids:
                threading.Thread(target=_run_surface_probe, args=(database, task_id), daemon=True).start()
        except sqlite3.Error:
            pass
        threading.Event().wait(SCHEDULER_WAKE_SECONDS)


def start_surface_scheduler(database):
    global _scheduler_started
    with _scheduler_guard:
        if _scheduler_started:
            return
        _scheduler_started = True
        threading.Thread(target=_surface_scheduler, args=(database,), daemon=True, name="cyberseek-surface-monitor").start()


def _surface_report(task):
    try:
        return json.loads(task["result"]) if task and task["result"] else None
    except json.JSONDecodeError:
        return None


def _surface_progress_items(task):
    try:
        items = json.loads(task.get("progress_items") or "[]")
        return [item for item in items if isinstance(item, dict) and item.get("item")]
    except (TypeError, ValueError, json.JSONDecodeError):
        return []


def _surface_tasks(rows):
    tasks = []
    for row in rows:
        task = dict(row)
        try:
            task["selected_sources"] = [source for source in json.loads(task["sources"]) if source in DISCOVERY_SOURCES]
        except (TypeError, json.JSONDecodeError):
            task["selected_sources"] = []
        task["source_names"] = [DISCOVERY_SOURCES[source] for source in task["selected_sources"]]
        if task.get("target_type") != "domain":
            task["source_names"] = ["Direct probe"]
        task["target_label"] = _surface_target_label(task["target_type"])
        interval = int(task["interval_minutes"])
        task["interval_label"] = _surface_interval_label(interval, task["target_type"])
        task["interval_value"] = interval // 60 if interval % 60 == 0 else interval
        task["interval_unit"] = "hours" if interval % 60 == 0 else "minutes"
        tasks.append(task)
    return tasks


def register_surface_routes(app, database, db, current_user, login_required):
    @app.route("/monitoring/surface", methods=["GET", "POST"])
    @login_required
    def surface_monitoring():
        if request.method == "POST":
            client_name = request.form.get("client_name", "").strip()
            target_type, target, target_error = _surface_target(request.form.get("target", ""))
            selected = [source for source in request.form.getlist("sources") if source in DISCOVERY_SOURCES]
            interval_minutes = _surface_interval(request.form)
            if len(client_name) < 2 or len(client_name) > 100:
                flash("Enter a client name between 2 and 100 characters.", "error")
            elif target_error:
                flash(target_error, "error")
            elif target_type == "domain" and resolves_to_non_public_ip(target):
                flash("Domains resolving to private, local, reserved, or non-public IP addresses are not allowed.", "error")
            elif target_type == "domain" and not selected:
                flash("Select at least one discovery source.", "error")
            elif not interval_minutes:
                flash("Set a polling interval from 1 hour to 7 days.", "error")
            else:
                now = _utc_now().isoformat()
                task_id = str(uuid.uuid4())
                db().execute(
                    """INSERT INTO surface_tasks (id, user_id, client_name, domain, target_type, interval_minutes, sources, status, result, error,
                    created_at, updated_at, last_run_at, next_run_at, is_private)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'Queued', NULL, NULL, ?, ?, NULL, ?, ?)""",
                    (task_id, current_user()["id"], client_name, target, target_type, interval_minutes, json.dumps(selected), now, now, now, is_private_task(request.form)),
                )
                db().commit()
                threading.Thread(target=_run_surface_probe, args=(database, task_id), daemon=True).start()
                flash("Surface monitoring started. Probes continue while you use other views.", "success")
                return redirect(url_for("surface_monitoring"))
        history = module_history(db(), "surface", current_user()["id"], request.args)
        history["items"] = _surface_tasks(history["items"])
        return render_template("surface.html", history=history, sources=DISCOVERY_SOURCES)

    @app.get("/monitoring/surface/<task_id>")
    @login_required
    def view_surface_task(task_id):
        task = visible_task(db(), "surface_tasks", task_id, current_user()["id"])
        if not task:
            flash("Surface monitoring task not found.", "error")
            return redirect(url_for("surface_monitoring"))
        task = dict(task)
        task["interval_label"] = _surface_interval_label(task["interval_minutes"], task["target_type"])
        task["target_label"] = _surface_target_label(task["target_type"])
        task["progress_items"] = _surface_progress_items(task)
        task["progress_by_item"] = {entry["item"]: entry.get("progress", 0) for entry in task["progress_items"]}
        return render_template("surface_task.html", task=task, report=_surface_report(task))

    @app.post("/monitoring/surface/<task_id>/delete")
    @login_required
    def delete_surface_task(task_id):
        delete_owned_task(db(), "surface_tasks", task_id, current_user()["id"])
        db().commit()
        flash("Surface monitoring task deleted.", "success")
        return redirect(url_for("surface_monitoring"))

    @app.post("/monitoring/surface/<task_id>/settings")
    @login_required
    def update_surface_settings(task_id):
        client_name = request.form.get("client_name", "").strip()
        selected = [source for source in request.form.getlist("sources") if source in DISCOVERY_SOURCES]
        task = db().execute(
            "SELECT target_type, interval_minutes FROM surface_tasks WHERE id = ? AND user_id = ?", (task_id, current_user()["id"])
        ).fetchone()
        interval_minutes = _surface_interval(request.form)
        if not task:
            flash("Surface monitoring task not found.", "error")
        elif len(client_name) < 2 or len(client_name) > 100:
            flash("Enter a client name between 2 and 100 characters.", "error")
        elif task["target_type"] == "domain" and not selected:
            flash("Select at least one discovery source.", "error")
        elif not interval_minutes:
            flash("Set a polling interval from 1 hour to 7 days.", "error")
        else:
            next_poll = _utc_now() + _surface_poll_delta(task["target_type"], interval_minutes)
            updated = db().execute(
                """UPDATE surface_tasks SET client_name = ?, interval_minutes = ?, sources = ?,
                next_run_at = CASE WHEN status = 'Monitoring' THEN ? ELSE next_run_at END,
                updated_at = ? WHERE id = ? AND user_id = ?""",
                (client_name, interval_minutes, json.dumps(selected), next_poll.isoformat(), _utc_now().isoformat(), task_id, current_user()["id"]),
            ).rowcount
            db().commit()
            flash("Surface monitoring settings updated." if updated else "Surface monitoring task not found.", "success" if updated else "error")
        return redirect(url_for("surface_monitoring"))

    @app.post("/monitoring/surface/<task_id>/poll-now")
    @login_required
    def poll_surface_now(task_id):
        task = db().execute(
            "SELECT status FROM surface_tasks WHERE id = ? AND user_id = ?", (task_id, current_user()["id"])
        ).fetchone()
        destination = "view_surface_task" if request.form.get("return_to") == "view" else "surface_monitoring"
        if not task:
            flash("Surface monitoring task not found.", "error")
        elif task["status"] == "Paused":
            flash("Resume the monitor before starting an immediate probe.", "error")
        elif task["status"] == "Running":
            flash("A surface probe is already running.", "error")
        else:
            now = _utc_now().isoformat()
            db().execute(
                "UPDATE surface_tasks SET status = 'Queued', error = NULL, next_run_at = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (now, now, task_id, current_user()["id"]),
            )
            db().commit()
            threading.Thread(target=_run_surface_probe, args=(database, task_id), daemon=True).start()
            flash("Immediate surface probe started.", "success")
        return redirect(url_for(destination, task_id=task_id) if destination == "view_surface_task" else url_for(destination))

    @app.post("/monitoring/surface/<task_id>/state")
    @login_required
    def update_surface_state(task_id):
        requested_state = request.form.get("state", "").lower()
        if requested_state not in {"pause", "resume"}:
            flash("Unsupported monitoring state.", "error")
            return redirect(url_for("surface_monitoring"))
        now = _utc_now().isoformat()
        if requested_state == "pause":
            updated = db().execute(
                "UPDATE surface_tasks SET status = 'Paused', updated_at = ? WHERE id = ? AND user_id = ?",
                (now, task_id, current_user()["id"]),
            ).rowcount
            message = "Surface monitoring paused."
        else:
            updated = db().execute(
                "UPDATE surface_tasks SET status = 'Queued', error = NULL, next_run_at = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (now, now, task_id, current_user()["id"]),
            ).rowcount
            if updated:
                threading.Thread(target=_run_surface_probe, args=(database, task_id), daemon=True).start()
            message = "Surface monitoring resumed."
        db().commit()
        flash(message if updated else "Surface monitoring task not found.", "success" if updated else "error")
        return redirect(url_for("surface_monitoring"))
