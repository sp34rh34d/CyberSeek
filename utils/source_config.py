import configparser
import os
from pathlib import Path


CONFIG_PATH = Path(os.getenv("CYBERSEEK_HOME") or Path(__file__).resolve().parent.parent) / "config.ini"
SOURCE_DEFAULTS = {
    "virustotal_api_key": "",
    "kaspersky_otip_api_key": "",
    "phishtank_api_key": "",
    "urlhaus_api_key": "",
    "malwarebazaar_api_key": "",
    "otx_api_key": "",
    "abuseipdb_api_key": "",
    "shodan_api_key": "",
    "hybrid_analysis_api_key": "",
    "filescan_api_key": "",
    "ai_provider": "openai",
    "ai_api_key": "",
    "ai_model": "",
}


def source_api_settings():
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read(CONFIG_PATH, encoding="utf-8")
    configured = dict(SOURCE_DEFAULTS)
    if parser.has_section("source_apis"):
        configured.update({key: parser.get("source_apis", key, fallback=value) for key, value in SOURCE_DEFAULTS.items()})
    return configured


def save_source_api_settings(updates):
    current = source_api_settings()
    for key in SOURCE_DEFAULTS:
        if key == "ai_provider":
            provider = updates.get(key, current[key]).strip().lower()
            current[key] = provider if provider in {"openai", "grok", "claude", "gemini"} else "openai"
        elif updates.get(key, "").strip():
            current[key] = updates[key].strip()
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read(CONFIG_PATH, encoding="utf-8")
    if not parser.has_section("source_apis"):
        parser.add_section("source_apis")
    parser.remove_option("source_apis", "xposedornot_api_key")
    for key, value in current.items():
        parser.set("source_apis", key, value)
    with CONFIG_PATH.open("w", encoding="utf-8") as destination:
        parser.write(destination)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass
    return current
