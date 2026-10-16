"""Registry of Cyberseek task modules shared by navigation, dashboard, search, and live status."""

ICONS = {
    "overview": '<rect x="1.8" y="1.8" width="5.4" height="5.4" rx="1"/><rect x="8.8" y="1.8" width="5.4" height="5.4" rx="1"/><rect x="1.8" y="8.8" width="5.4" height="5.4" rx="1"/><rect x="8.8" y="8.8" width="5.4" height="5.4" rx="1"/>',
    "dns": '<circle cx="8" cy="3" r="1.6"/><circle cx="3" cy="13" r="1.6"/><circle cx="13" cy="13" r="1.6"/><path d="M8 4.6V9M8 9 3.7 11.7M8 9l4.3 2.7"/>',
    "whois": '<rect x="1.5" y="3" width="13" height="10" rx="1.2"/><circle cx="5.2" cy="7.3" r="1.3"/><path d="M3.3 11c.5-1.4 1.6-2 1.9-2s1.4.6 1.9 2M9 6.5h4M9 9.3h4"/>',
    "blacklist": '<path d="M8 1.6 13.5 3.4v4.3c0 3.6-2.4 5.9-5.5 7-3.1-1.1-5.5-3.4-5.5-7V3.4L8 1.6Z"/><path d="M5.5 5.5l5 5"/>',
    "spf": '<rect x="1.5" y="3.5" width="13" height="9" rx="1"/><path d="M1.8 4l6.2 5 2-1.6M11.3 9.2l1.3 1.3 2.4-2.6"/>',
    "file_scan": '<path d="M4 1.6h5.2L12 4.4V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2.6a1 1 0 0 1 1-1Z"/><path d="M9.2 1.6V4.4H12"/><circle cx="8.2" cy="10" r="2"/><path d="M9.7 11.5 11 12.8"/>',
    "reputation": '<circle cx="7" cy="7" r="4.3"/><path d="M10.1 10.1 14 14"/>',
    "live_url": '<circle cx="8" cy="8" r="6.2"/><path d="M1.8 8h12.4M8 1.8c1.7 1.7 2.6 4 2.6 6.2s-.9 4.5-2.6 6.2c-1.7-1.7-2.6-4-2.6-6.2s.9-4.5 2.6-6.2Z"/>',
    "eml": '<rect x="1.5" y="3.2" width="10.5" height="8" rx="1"/><path d="M1.8 3.7l5.1 4 5.1-4"/><circle cx="12.3" cy="11.7" r="2.1"/><path d="M13.8 13.2 15 14.4"/>',
    "surface": '<circle cx="8" cy="8" r="1"/><circle cx="8" cy="8" r="3.6" stroke-dasharray="2 2"/><circle cx="8" cy="8" r="6.2"/>',
    "email_exposure": '<rect x="1.5" y="3.5" width="13" height="9" rx="1"/><path d="M1.8 4l6.2 5 6.2-5"/>',
    "users": '<circle cx="8" cy="5" r="2.6"/><path d="M2.5 14c1-3 3-4.5 5.5-4.5s4.5 1.5 5.5 4.5"/>',
    "source_apis": '<circle cx="5" cy="8" r="3"/><path d="M7.8 8h6.2M11 8v2.3M13 8v1.6"/>',
}

# key: table, label, sidebar group, list/view endpoints, URL prefixes that mark the menu item
# active, columns searched by the history filter, the column shown as the task title, and
# the query parameters used to pre-fill the form when re-running a task.
MODULES = {
    "dns": {
        "table": "dns_tasks", "label": "DNS query", "group": "Reconnaissance",
        "list": "dns_queries", "view": "view_dns_task", "prefixes": ("/recon/dns",),
        "search": ("domain", "record_type"), "title": "domain",
        "rerun": {"domain": "domain", "record_type": "record_type"},
    },
    "whois": {
        "table": "whois_tasks", "label": "WHOIS lookup", "group": "Reconnaissance",
        "list": "whois_lookup", "view": "view_whois_task", "prefixes": ("/recon/whois",),
        "search": ("target",), "title": "target", "rerun": {"target": "target"},
    },
    "blacklist": {
        "table": "blacklist_tasks", "label": "Blacklist check", "group": "Reconnaissance",
        "list": "blacklist_check", "view": "view_blacklist_task", "prefixes": ("/recon/blacklist",),
        "search": ("target",), "title": "target", "rerun": {"target": "target"},
    },
    "spf": {
        "table": "spf_tasks", "label": "SPF check", "group": "Reconnaissance",
        "list": "spf_check", "view": "view_spf_task", "prefixes": ("/recon/spf",),
        "search": ("domain", "sender_ip"), "title": "domain",
        "rerun": {"domain": "domain", "sender_ip": "sender_ip"},
    },
    "file_scan": {
        "table": "file_scan_tasks", "label": "File scan", "group": "Analysis",
        "list": "file_scan", "view": "view_file_scan", "prefixes": ("/analysis/file",),
        "search": ("filename",), "title": "filename", "rerun": None,
    },
    "reputation": {
        "table": "reputation_tasks", "label": "Reputation lookup", "group": "Analysis",
        "list": "reputation_lookup", "view": "view_reputation_lookup",
        "prefixes": ("/analysis/reputation", "/analysis/url"),
        "search": ("target",), "title": "target", "rerun": {"target": "target"},
    },
    "live_url": {
        "table": "live_url_tasks", "label": "Live URL analysis", "group": "Analysis",
        "list": "live_url_analysis", "view": "view_live_url_analysis", "prefixes": ("/analysis/live-url",),
        "search": ("target",), "title": "target", "rerun": {"target": "target"},
    },
    "eml": {
        "table": "eml_tasks", "label": "EML scan", "group": "Analysis",
        "list": "eml_analysis", "view": "view_eml_analysis", "prefixes": ("/analysis/eml",),
        "search": ("filename",), "title": "filename", "rerun": None,
    },
    "surface": {
        "table": "surface_tasks", "label": "Surface", "group": "Monitoring",
        "list": "surface_monitoring", "view": "view_surface_task", "prefixes": ("/monitoring/surface",),
        "search": ("domain", "client_name"), "title": "domain", "rerun": None,
    },
    "email_exposure": {
        "table": "email_exposure_tasks", "label": "Email exposure", "group": "Monitoring",
        "list": "email_exposure", "view": "view_email_exposure", "prefixes": ("/monitoring/email-exposure",),
        "search": ("email",), "title": "email", "rerun": {"email": "email"},
    },
}

GROUPS = ("Reconnaissance", "Analysis", "Monitoring")
ADMIN_ITEMS = (
    {"key": "users", "label": "Users", "endpoint": "manage_users", "prefixes": ("/admin/users",)},
    {"key": "source_apis", "label": "Source APIs", "endpoint": "source_apis", "prefixes": ("/admin/source-apis",)},
)
# Local IoC observations record the module that produced them under these source kinds.
IOC_SOURCE_MODULES = ("reputation", "blacklist", "file_scan", "live_url")
VIEW_ENDPOINTS = {module["view"]: key for key, module in MODULES.items()}


def navigation():
    """Sidebar groups in display order."""
    groups = [{"label": group, "items": [
        {"key": key, "label": module["label"], "endpoint": module["list"], "prefixes": module["prefixes"]}
        for key, module in MODULES.items() if module["group"] == group
    ]} for group in GROUPS]
    return groups


def rerun_args(key, task):
    """Query parameters that pre-fill the module form with the task's original input."""
    mapping = MODULES[key]["rerun"]
    if not mapping:
        return None
    keys = task.keys() if hasattr(task, "keys") else task
    return {param: task[column] for param, column in mapping.items() if column in keys and task[column]}
