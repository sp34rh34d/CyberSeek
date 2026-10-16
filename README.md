# Cyberseek

Cyberseek is a **local threat-intelligence and defensive-analysis workspace** for security teams. It brings asset visibility, reconnaissance, indicator enrichment, email inspection, and file or URL analysis into one focused interface, and keeps a local task history and analyst context so an investigation can be reviewed, shared, and exported.

It is designed to **support investigation and prioritization**. It is not an exploitation framework, an internet-wide scanner, or a replacement for endpoint protection, a SIEM, or a managed sandbox. Use it only for assets, files, mailboxes, and indicators that you are **authorized** to assess.

---

## Contents

- [Key features](#key-features)
- [How the workspace works](#how-the-workspace-works)
- [Modules in detail](#modules-in-detail)
  - [Workspace: Overview & Search](#workspace-overview--search)
  - [Reconnaissance: DNS, WHOIS, Blacklist, SPF](#reconnaissance)
  - [Analysis: Reputation, Live URL, EML, File scan](#analysis)
  - [Monitoring: Surface, Email exposure](#monitoring)
  - [Administrative: Users, Source APIs](#administrative)
- [AI-assisted SOC summaries](#ai-assisted-soc-summaries)
- [Worked investigations](#worked-investigations)
- [Configuration](#configuration)
- [Data, privacy & retention](#data-privacy--retention)
- [Security controls](#security-controls)
- [Requirements](#requirements)
- [Installation](#installation)
- [Development & testing](#development--testing)
- [Project layout](#project-layout)

<img width="1643" height="910" alt="Captura de pantalla 2026-10-16 a la(s) 3 58 27 p  m" src="https://github.com/user-attachments/assets/66ced070-ea8d-482e-bf2a-db3870eef822" />

---

## Key features

- **Eleven analysis modules** across reconnaissance, analysis, and monitoring, all in one interface.
- **Local intelligence store** that correlates every domain, URL, IP, hash, and file you observe, and flags indicators that came back malicious or suspicious.
- **Cross-module search and pivots** — look up any indicator and jump to the module that can investigate it, with the form pre-filled.
- **Shared, reviewable task history** with ownership, optional private visibility, server-side filtering, pagination, and live status that updates without reloading.
- **Analyst notes** on every task, visible to everyone who can see the task.
- **Exports** — JSON and HTML reports per task, plus dedicated IoC exports where the module supports them.
- **MITRE ATT&CK mapping** where the evidence supports it.
- **Optional AI SOC summaries** (OpenAI, xAI Grok, Anthropic Claude, or Google Gemini) that are evidence-bound and always fall back to a local summary.
- **Safe by design** — SSRF protections, a sandboxed email preview, non-executing file analysis, CSRF protection, a strict content-security policy, optional TOTP two-factor authentication, and no third-party code loaded in the browser.
- **Light and dark themes**, follows the operating-system preference, and adapts to mobile screens.

---

## How the workspace works

A few concepts are shared by every module. Understanding them is the fastest way to get value out of the tool.

**Tasks.** Every action you run — a DNS query, a file scan, a surface monitor — creates a *task*. Tasks run in the background, so you can start one and keep working; its status moves through `Queued → Running → Complete` (or `Failed`). You never have to wait on a page.

**Live status, no reload.** While a task runs, its badge updates in place. A task report page refreshes itself once, automatically, the moment the task finishes. If the service is restarted while a task is still running, that task is marked `Failed` with an explanatory note at the next start-up instead of being stuck forever.

**Ownership and visibility.** Each task records who created it. By default tasks are **shared** so the team can review them; tick *"Keep this task private"* to make a task visible only to you. Private tasks of other analysts are never shown to you — not in lists, not in search, not in the overview.

**Task history.** Each module keeps a paginated history (24 per page). Search by target or owner, filter by status, owner, or date, and click a stat card (Total / Active / Complete / Failed) to filter by that status. **Run again** reopens the module form pre-filled with a task's original input.

**Local intelligence.** Reputation, Blacklist, File scan, and Live URL results feed a local SQLite indicator store. Every domain, URL, IP, and hash you see is tracked with how often it was observed and whether sources flagged it. The **Overview** surfaces the ones that came back malicious or suspicious, and **Search** lets you look any of them up.

**Pivots.** Wherever an indicator appears — a search result, or the "Indicators observed in this task" block at the bottom of a report — Cyberseek offers one-click buttons to investigate it in the relevant module, with the form already filled in. This is how you turn one finding into the next step without retyping anything.

**Notes.** Every task report ends with a shared **analyst notes** thread. Record context, decisions, or follow-ups (e.g. *"Confirmed phishing kit; blocked at the proxy, ticket SOC-1234"*). Notes are visible to everyone who can see the task; only the author can delete a note.

**Exports.** Every completed task exports to **JSON** (structured data) and **HTML** (a standalone report). Reputation, Live URL, and File scan additionally export a dedicated **IoC list** in JSON, ready to feed into other tooling.

---

## Modules in detail

### Workspace: Overview & Search

**Overview** is the landing page and your situational picture:

- **Active now**, **tasks in the last 7 days**, and **failures in the last 7 days** across every module.
- **Source APIs configured** (and whether AI is on).
- **Latest tasks** from every module, newest first, each linking to its report.
- **Flagged indicators** — everything local intelligence has marked malicious or suspicious, newest first.
- A **module grid** showing per-module totals, active work, and recent failures.

*How to use it:* start your shift here. The failure counter tells you what needs re-running; the flagged indicators tell you what to chase; the module cards tell you where the activity is.

**Search** (top bar, or press `/` anywhere) is the fastest way to find and pivot:

- Enter a **domain, IP, URL, file hash, email address, or file name**.
- Matching **tasks** across all modules and matching **indicators** from the local store are listed.
- When your query is a recognisable indicator, Cyberseek offers **pivot buttons** that open the right module pre-filled — e.g. searching an IP offers WHOIS, DNS (PTR), Blacklist, and Reputation.
- Results respect visibility: another analyst's private tasks never appear.

---

### Reconnaissance

#### DNS query

Resolves a public target using `A`, `AAAA`, `TXT`, `NS`, `CNAME`, `PTR`, `MX`, `SOA`, `DS`, or `ALL` records.

- **Input:** a domain, hostname, or IP. Private, local, reserved, and non-public targets (and names that resolve to them) are rejected.
- **How to use:** enter the target, pick a record type (or `ALL`), optionally mark it private, and run. For an IP, use `PTR` for the reverse record.
- **Report:** records grouped by type, geolocation context for public addresses with a map, and per-task JSON/HTML export.
- **Pivot from Search:** searching an IP pre-fills DNS with the `PTR` record type.

#### WHOIS lookup

Investigates registration and ownership for a public IP, domain, or hostname.

- **Report:** registrar, creation/expiration dates, nameservers, registrant and contact fields, country, network ownership, and a location view when public address data is available.
- **Use it to:** judge a domain's age (freshly registered domains are a phishing signal), find the responsible network, and confirm ownership before escalating.

#### Blacklist check

Compares a public domain, hostname, or IP against a catalog of **DNS block-lists** — Spamhaus (ZEN/SBL/XBL/PBL), Barracuda, SpamCop, SORBS, and UCEPROTECT (Levels 1–3). **No API keys required.**

- **Report:** a per-provider table with clear states — **clean**, **listed**, **unavailable**, or **unknown** — and a delisting link where the provider exposes one.
- **Use it to:** check whether your own sending IP/domain is listed (deliverability), or whether a suspicious host already has a poor reputation.

#### SPF check

Parses a domain's sender policy and validates common implementation risks:

- Record publication, deprecated syntax, multiple records, invalid trailing content, syntax errors, the 10-lookup `include` limit, recursive loops, duplicate includes, `ptr` usage, and void lookups.
- Optionally checks whether a **specific public sender IP** is permitted by the policy.
- **Use it to:** audit your own domains for email-spoofing resistance, or verify whether a given IP was authorized to send as a domain seen in a phishing header.

---

### Analysis

#### Reputation lookup

Checks a **hostname, domain, IP, URL, or file hash** against one, several, or all configured sources, then correlates the answers.

- **Sources:** Local heuristics, VirusTotal, Kaspersky OpenTIP, PhishTank, Cisco Talos, URLhaus, MalwareBazaar, AlienVault OTX, AbuseIPDB. VirusTotal and Kaspersky need API keys; Talos opens its public lookup; the others use their respective keys where configured.
- **Report tabs:** an **overview** with the verdict and (for URLs/files) a VirusTotal engine distribution, **network intelligence** (associated IPs, subdomains, files, dates), **engine results** (filterable, showing which engines flagged it), and **related indicators** from local correlation. Plus a network location map and an **IoC export**.
- **How to read it:** agreement across independent sources is a strong signal; a single detection is worth taking seriously but should be corroborated. The AI/local summary states this for you.

#### Live URL analysis

Renders a public URL in a **disposable headless browser profile** and reports what actually happens.

- **Input:** a public `http`/`https` URL. Private, local, and non-public destinations are blocked, and the fetch is pinned to the resolved public IP to prevent DNS-rebinding.
- **Choose a user agent:** Firefox (default), Chrome, Microsoft Edge, or Safari — useful when a page serves different content per browser.
- **Report:** a **screenshot**, loaded network resources, observed behavior, **security-header** posture, **reputation** context (VirusTotal), domain/network context with a map, extracted **IoCs**, and MITRE-aligned patterns — organized in tabs, with an AI/local **correlated verdict**.
- **Use it to:** safely see a suspicious link's real content and behavior without visiting it yourself.

#### EML scan

Ingests `.eml` and `.msg` messages **safely** for phishing triage.

- **Report:** headers, the received time normalized to a reporting timezone you choose, **SPF / DKIM / DMARC** and authentication results, sender domain and IP, a **sanitized body preview** (rendered in a locked-down sandboxed frame with scripts, remote images, and tracking pixels stripped), extracted links, attachment metadata, and available reputation context.
- **Attachments** can be downloaded as a **password-protected ZIP** (password: `infected`) so a sample never lands on disk unprotected.
- **How to use it:** upload the reported message, set the timezone to match the report, then read the authentication results and sender IP first, check the links and attachments against Reputation/Live URL via the pivots, and record your disposition in the notes.

#### File scan

Always runs a **local static analysis first**, and the uploaded file is **never executed** locally.

- **Static (always):** SHA-256/SHA-1/MD5 hashes, printable strings, embedded artifacts, local heuristics, extracted IoCs, and optional known-hash reputation (Hybrid Analysis or Filescan.io). Password-protected archives are supported — provide the archive password; it is used only for the scan and never stored.
- **Dynamic (optional):** select **Hybrid Analysis** or **Filescan.io** to detonate the sample in an external sandbox (Windows, Linux, or Android profile, chosen automatically). The dynamic report organizes observed actions, commands, MITRE classification, threat level, network connections, **AI-assisted action triage**, and IoCs in separate tabs, and keeps polling the provider until the verdict is ready.
- **Use it to:** triage a suspicious attachment or binary locally, and escalate to a sandbox only when you need behavioral evidence and have authorization to submit the sample externally.

---

### Monitoring

#### Surface

Continuously watches an authorized **domain, public IP, or CIDR range** for new exposure.

- **Discovery sources:** crt.sh and Internet Archive (queried directly), plus VirusTotal, AlienVault OTX, and Shodan (where keys are configured). IP and CIDR targets use direct public-address probes; a CIDR is limited to a bounded number of public addresses.
- **Tracks:** discovered hostnames, response state, current IP, owner/ISP, newly observed services and ports, polling progress, and which source supplied each piece of evidence.
- **Controls:** choose sources per task, set a polling interval (1 hour to 7 days), **pause/resume** a monitor, **edit** it, or **poll now** to force an immediate run.
- **Use it to:** keep an eye on an organization's known footprint and get alerted — on the next poll — to new hostnames, ports, or services.

#### Email exposure

Checks whether a single authorized **email address** appears in known breach data.

- **Report:** whether the address was found and the breach year for each matching record.
- **Scope:** one address at a time; domain-wide and password checks are intentionally out of scope.

---

### Administrative

Visible to administrators only.

#### Users

Create analyst or administrator accounts, reset temporary passwords, change roles, and remove accounts. **Public registration is disabled.** New accounts must change their password at first sign-in. You cannot change your own role or delete your own account.

#### Source APIs

Stores the optional credentials and model settings used by the intelligence sources, the dynamic sandboxes, and the AI summaries. Values are written to the local `config.ini` and are never displayed again after saving (leave a field blank to keep its current value). The help link next to the AI section points to the right console for the selected provider.

| Setting | Used by | Needs a key? |
|---|---|---|
| VirusTotal | Reputation, Live URL, EML, Surface | Yes |
| Kaspersky OpenTIP | Reputation | Yes |
| PhishTank | Reputation | Optional |
| URLhaus / MalwareBazaar | Reputation | Shared abuse.ch Auth-Key |
| AlienVault OTX | Reputation, Surface | Yes |
| AbuseIPDB | Reputation | Yes |
| Shodan | Surface | Yes |
| Hybrid Analysis / Filescan.io | File scan (hash reputation + dynamic sandbox) | Yes |
| AI SOC Analyst | Reputation, Live URL, File scan summaries | Yes (provider API key) |

Cisco Talos (Reputation) and the DNS block-lists (Blacklist check) need no keys.

---

## AI-assisted SOC summaries

When an AI provider is configured in **Source APIs**, three places gain an evidence-bound SOC summary written in an analyst's voice:

- **Reputation lookup** — a triage assessment with severity, evidence, coverage, recommendations, and limitations.
- **Live URL analysis** — a correlated verdict with confidence and recommended response actions.
- **File scan (dynamic)** — a sandbox assessment plus per-action threat triage.

Supported providers: **OpenAI**, **xAI Grok**, **Anthropic Claude**, **Google Gemini**. The AI is told to assess only the supplied evidence and not to invent telemetry or attribution. **Every summary falls back to a local, rule-based version** if the provider is unavailable, so the report is never blank — and the panel always labels which one you are reading (the provider's name, or *"Local correlation"*). **AI output is advisory and must be reviewed by an analyst.**

---

## Worked investigations

**A reported phishing email.**
1. **EML scan** → upload the message, set the timezone. Read the authentication results (SPF/DKIM/DMARC) and the sender IP.
2. From the report's indicators, **pivot** the sender IP to **Reputation** and **Blacklist**, and the links to **Live URL analysis**.
3. **Live URL** renders the link safely — confirm whether it's a credential-harvesting page from the screenshot and behavior.
4. Record the disposition in **analyst notes**, and **export** the EML and Live URL reports for the ticket.

**A suspicious IP from your SIEM.**
1. **Search** the IP → pivot to **WHOIS** (who owns it), **DNS** (PTR), **Blacklist** (known-bad?), and **Reputation** (multi-source verdict).
2. If Reputation flags associated domains or files, pivot those too — the indicators block makes each one one click away.
3. The IP now appears under **Overview → Flagged indicators** if any source marked it malicious/suspicious.

**A questionable attachment.**
1. **File scan** → upload; the local static pass runs immediately (hashes, strings, heuristics, known-hash reputation).
2. If you need behavior and are authorized to submit it, choose **Dynamic analysis** with Hybrid Analysis or Filescan.io.
3. Pivot the extracted network IoCs to **Reputation**/**Live URL**, and keep the IoC export for hunting.

---

## Configuration

### Service

The optional `[service]` section of `config.ini` configures the local listener and session behavior:

```ini
[service]
PERMANENT_SESSION_LIFETIME = 10
INTERFACE = 127.0.0.1
PORT = 5000
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = Lax
WTF_CSRF_SSL_STRICT = False
UPLOAD_RETENTION_DAYS = 0
```

- `PERMANENT_SESSION_LIFETIME` is in minutes.
- `INTERFACE` defaults to `127.0.0.1` (local only). Bind to `0.0.0.0` **only** behind TLS and authentication you control.
- `UPLOAD_RETENTION_DAYS` deletes stored samples of finished tasks after that many days (`0`, the default, keeps them; reports are kept either way, but attachment downloads for purged tasks stop working).
- For an **HTTPS deployment**, enable `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `WTF_CSRF_SSL_STRICT`.
- Forwarded client-IP headers (`X-Forwarded-For` / `X-Real-IP`) are trusted **only** when the direct connection is from `127.0.0.1` or `::1`; otherwise they are ignored.

### Environment (`.env`)

```
SECRET_KEY=replace-with-a-long-random-value
MAX_CONTENT_LENGTH=16777216
```

Set a long, persistent `SECRET_KEY` for any non-local deployment (if it is unset, a random key is generated at start-up and sessions reset on every restart). `FLASK_DEBUG` must stay off in production.

### Source API keys

Configure these in the **Source APIs** admin view (see the table above). They are stored in `config.ini`. Keep `config.ini` and `.env` out of source control (they are git-ignored).

---

## Data, privacy & retention

- Task metadata, local correlations, source results, analyst notes, and user accounts live in `instance/cyberseek.db`.
- Uploaded samples are stored under `uploads/` **without execute permissions**; Live URL screenshots under `instance/live_url_captures/`.
- An external dynamic sandbox receives a file **only** when the analyst explicitly selects Dynamic analysis and a provider. Reputation, Live URL, and Email-exposure likewise send the submitted indicator to the selected external service — submitting an indicator discloses it to that service.
- Two-factor secrets are encrypted at rest; keep `instance/.two_factor.key` with the local application data.
- Set `UPLOAD_RETENTION_DAYS` to purge old samples automatically.

---

## Security controls

- **Authentication:** mandatory login; a default `admin` / `arasaka` bootstrap account that must change its password on first use. Change it immediately, and prefer a non-default password on any shared deployment.
- **Two-factor (optional):** per-user TOTP with a QR setup flow compatible with standard authenticator apps; enabled accounts require a six-digit code after the password.
- **Authorization:** administrators control account creation; analysts cannot reach admin views; every task respects its owner's privacy setting.
- **Brute-force protection:** repeated failed sign-ins quarantine the source IP, with an increasing interval for repeat offenders.
- **CSRF protection** on all state-changing forms, with a constant-time token check.
- **Content-Security-Policy** with a per-request nonce; fonts and JavaScript libraries are served locally, so pages load **no third-party code** (map tiles are the only external resource). Plus `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`, and HSTS over HTTPS.
- **SSRF defense:** reconnaissance and analysis modules reject private, loopback, link-local, and reserved destinations; Live URL additionally pins the connection to the resolved public IP and re-validates redirects.
- **Safe content handling:** the email preview is sanitized (scripts, styles, remote images/pixels, and frames removed) and rendered in a sandboxed, escaped frame; uploaded files are never executed by the local scanner; archives are read with zip-slip and decompression-size protections.

---

## Requirements

- **Python 3.9+** (developed and tested on recent CPython).
- **Linux, or macOS.**
- Network access only for the sources and providers you choose to configure.
- **Chromium** for Live URL analysis (Playwright). The Linux installer downloads it automatically into the service cache; for a local install, run `python -m playwright install chromium` once.

---

## Installation

### Local (macOS / Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium   # for Live URL analysis
cp .env.example .env
python app.py
```


Then open `http://127.0.0.1:5000`, sign in with `admin` / `arasaka`, and change the password immediately.

### Packaged install (`setup.py`)

```bash
sudo python3 setup.py install
```

Use `py setup.py install` from an Administrator PowerShell session on Windows. The installer creates a **private runtime** instead of modifying the system Python (`/opt/cyberseek` on Linux, `ProgramData\Cyberseek\runtime` on Windows). On Linux it also creates a restricted `cyberseek` system user and group, prepares `/var/lib/cyberseek` owned by that account, and starts the `cyberseek` systemd service. Data directories use `750` and files use `640`. The service `config.ini` is created at `/var/lib/cyberseek/config.ini`; existing configuration is preserved on re-run.

Update the application files only (preserving config, database, uploads, and browser cache):

```bash
sudo python3 setup.py update
```

Remove Cyberseek completely (package, service, database, uploads, screenshots, `.env`, `config.ini`; on Linux, also the managed user/group):

```bash
sudo python3 setup.py uninstall
```
---

Cyberseek supports investigation and prioritization. Always validate a finding against your own telemetry before making a disposition, and only assess assets, files, mailboxes, and indicators you are authorized to.
