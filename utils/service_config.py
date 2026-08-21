import configparser
import os
from pathlib import Path


CONFIG_PATH = Path(os.getenv("CYBERSEEK_HOME") or Path(__file__).resolve().parent.parent) / "config.ini"
SERVICE_DEFAULTS = {
    "PERMANENT_SESSION_LIFETIME": 10,
    "INTERFACE": "127.0.0.1",
    "PORT": 5000,
    "SESSION_COOKIE_SECURE": False,
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
    "WTF_CSRF_SSL_STRICT": False,
}


def _bounded_int(value, default, minimum, maximum):
    try:
        return min(maximum, max(minimum, int(value)))
    except (TypeError, ValueError):
        return default


def _boolean(parser, key):
    try:
        return parser.getboolean("service", key, fallback=SERVICE_DEFAULTS[key])
    except ValueError:
        return SERVICE_DEFAULTS[key]


def service_settings():
                                                                                  
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read(CONFIG_PATH, encoding="utf-8")
    if not parser.has_section("service"):
        return dict(SERVICE_DEFAULTS)

    same_site = parser.get("service", "SESSION_COOKIE_SAMESITE", fallback=SERVICE_DEFAULTS["SESSION_COOKIE_SAMESITE"]).strip().title()
    if same_site not in {"Lax", "Strict", "None"}:
        same_site = SERVICE_DEFAULTS["SESSION_COOKIE_SAMESITE"]
    return {
        "PERMANENT_SESSION_LIFETIME": _bounded_int(parser.get("service", "PERMANENT_SESSION_LIFETIME", fallback=10), 10, 1, 10080),
        "INTERFACE": parser.get("service", "INTERFACE", fallback=SERVICE_DEFAULTS["INTERFACE"]).strip() or SERVICE_DEFAULTS["INTERFACE"],
        "PORT": _bounded_int(parser.get("service", "PORT", fallback=5000), 5000, 1, 65535),
        "SESSION_COOKIE_SECURE": _boolean(parser, "SESSION_COOKIE_SECURE"),
        "SESSION_COOKIE_HTTPONLY": _boolean(parser, "SESSION_COOKIE_HTTPONLY"),
        "SESSION_COOKIE_SAMESITE": same_site,
        "WTF_CSRF_SSL_STRICT": _boolean(parser, "WTF_CSRF_SSL_STRICT"),
    }
