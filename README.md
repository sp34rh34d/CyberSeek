# Cyberseek

Cyberseek is a local threat-intelligence and defensive-analysis workspace for security teams. It brings asset visibility, reconnaissance, indicator enrichment, email inspection, and file or URL analysis into one focused interface while preserving a local task history and analyst context, it is designed to support investigation.

## Intelligence scope

Cyberseek turns analyst inputs into structured, reviewable evidence:

- Collects public DNS, WHOIS, SPF, reputation, and attack-surface intelligence.
- Correlates observed domains, URLs, IP addresses, hashes, and files in a local SQLite intelligence store.
- Preserves task ownership and optional private visibility while allowing team-wide review by default.
- Enriches results through the sources configured by an administrator; unavailable sources are shown as unavailable instead of being treated as clean.
- Produces exportable JSON and HTML reports, plus dedicated IoC exports where the module supports them.
- Maps observed or inferred behavior to MITRE ATT&CK where enough evidence is available.
- Uses an optionally configured AI provider to produce evidence-bound SOC summaries. AI output is advisory and must be reviewed by an analyst.

## Interface walkthrough

The following reference captures describe the interface and the purpose of every Cyberseek module.

### Administrative
**Users** is the account-control view. Administrators create analyst or administrator accounts, reset temporary passwords, change roles, and remove accounts. Public registration is disabled. New accounts must change their password at first sign-in.

**Source APIs** stores the optional credentials and model settings used by intelligence sources, dynamic sandboxes, and AI-assisted summaries. This view is only visible to administrators; its values are stored locally in `config.ini`.
<img width="1295" height="918" alt="Captura de pantalla 2026-08-20 a la(s) 11 47 27 p  m" src="https://github.com/user-attachments/assets/68ccbebc-30cc-424d-a165-c3d9b678ee2d" />

### Monitoring
**Surface** continuously monitors authorized domains, individual IPs, and IP ranges. It tracks discovered hostnames, response state, current IP, owner or ISP, newly observed services, ports, polling progress, and the sources that supplied the evidence. Sources can be selected per task and polls can be forced manually.

<img width="1621" height="715" alt="Captura de pantalla 2026-08-21 a la(s) 12 10 27 a  m" src="https://github.com/user-attachments/assets/369e3265-6480-4855-b5f1-11603e0b4a77" />

<img width="1611" height="879" alt="Captura de pantalla 2026-08-21 a la(s) 12 10 48 a  m" src="https://github.com/user-attachments/assets/a9d1514a-a6bc-4eee-9edf-658761641aae" />


**Email exposure** checks one authorized email address against the exposure source. It reports whether that address appears in known breach data and lists the breach year returned for each matching record. Domain-wide and password checks are not part of this module.

<img width="1622" height="460" alt="Captura de pantalla 2026-08-21 a la(s) 12 12 21 a  m" src="https://github.com/user-attachments/assets/36be88dd-5d2d-44c2-b4ed-b7d911bce8f1" />

### Reconnaissance

**DNS query** resolves public targets using `A`, `AAAA`, `TXT`, `NS`, `CNAME`, `PTR`, `MX`, `SOA`, `DS`, or `ALL` records. Results retain task status, structured output, geolocation context for public addresses, and per-task export actions. Private addresses and names resolving to private addresses are rejected.
<img width="1625" height="930" alt="Captura de pantalla 2026-08-21 a la(s) 12 13 37 a  m" src="https://github.com/user-attachments/assets/7a375be5-e23a-4efb-ab8a-edb0f26f769e" />


**WHOIS lookup** investigates a public IP address, domain, or hostname. It presents available registrar, creation and expiration dates, nameservers, registrant and contact fields, country, network ownership, and a location view when public address data is available.
<img width="1626" height="958" alt="Captura de pantalla 2026-08-21 a la(s) 12 14 37 a  m" src="https://github.com/user-attachments/assets/aa51d14a-3d28-49c0-854b-2fb8dac4e419" />


**Blacklist check** compares a public domain, hostname, or IP address with supported reputation and block-list sources. The result table uses clear state labels such as clean, listed, unavailable, or unknown, and offers provider delisting links only when a provider exposes one.
<img width="1623" height="904" alt="Captura de pantalla 2026-08-21 a la(s) 12 15 29 a  m" src="https://github.com/user-attachments/assets/c60b554b-61c7-427c-9317-5671d6d6de66" />



**SPF check** parses a domain's sender policy and validates common implementation risks: record publication, deprecated syntax, multiple records, invalid trailing content, syntax, include lookup volume, recursive loops, duplicate includes, PTR usage, and void lookups. It can also check whether a submitted public sender IP is permitted for the domain.
<img width="1628" height="955" alt="Captura de pantalla 2026-08-21 a la(s) 12 16 13 a  m" src="https://github.com/user-attachments/assets/1c841f64-425d-420b-beeb-a3441dc14ef8" />



### Analysis
**Reputation lookup** accepts a hostname, domain, IP address, URL, or file hash. Analysts choose one, two, or all configured sources. The result view separates provider verdicts from associated intelligence: public IPs, subdomains, files, dates, engine distribution, malicious or suspicious engine results, local historical correlation, a network location view, and IoC export.
<img width="1625" height="721" alt="Captura de pantalla 2026-08-21 a la(s) 12 17 09 a  m" src="https://github.com/user-attachments/assets/ff2e6374-fa45-411e-9229-45f18e30cf81" />

<img width="1622" height="858" alt="Captura de pantalla 2026-08-21 a la(s) 12 17 30 a  m" src="https://github.com/user-attachments/assets/79248d1c-8cde-41e2-9958-336dc860df0d" />

<img width="1609" height="888" alt="Captura de pantalla 2026-08-21 a la(s) 12 17 41 a  m" src="https://github.com/user-attachments/assets/11bb08c7-ac3b-4013-91d9-f7a9835746eb" />



**Live URL analysis** renders a public URL using a disposable browser profile and reports loaded resources, visible behavior, screenshot evidence, domain registration context, network information, security headers, reputation context, IoCs, and MITRE-aligned patterns. User-agent selection is explicit and defaults to Firefox. The module blocks private or local destinations.
<img width="1624" height="955" alt="Captura de pantalla 2026-08-21 a la(s) 12 19 17 a  m" src="https://github.com/user-attachments/assets/f1ba1400-246f-4b3e-8331-a11ec6338043" />

<img width="1628" height="964" alt="Captura de pantalla 2026-08-21 a la(s) 12 19 31 a  m" src="https://github.com/user-attachments/assets/37977506-a785-4430-9eaa-ee60fe0d8294" />

<img width="1623" height="963" alt="Captura de pantalla 2026-08-21 a la(s) 12 19 42 a  m" src="https://github.com/user-attachments/assets/e0053417-b6a1-451b-865a-92009a6c821e" />

<img width="1627" height="941" alt="Captura de pantalla 2026-08-21 a la(s) 12 19 57 a  m" src="https://github.com/user-attachments/assets/eb0a4dbd-1d3e-4b1a-ad5d-83fdc524174c" />


**EML scan** ingests `.eml` and `.msg` mail safely. It extracts headers, normalized received time according to the selected reporting timezone, SPF, DKIM, DMARC, authentication results, sender domain and IP, body preview, links, attachment metadata, and available reputation context. Attachments may be downloaded as a password-protected archive using the password `infected`.

<img width="1623" height="955" alt="Captura de pantalla 2026-08-21 a la(s) 12 22 57 a  m" src="https://github.com/user-attachments/assets/945f88ae-4d1b-44f9-b348-cc6bbf545cf3" />

<img width="1627" height="921" alt="Captura de pantalla 2026-08-21 a la(s) 12 23 08 a  m" src="https://github.com/user-attachments/assets/c8d17379-c471-471f-8a83-987d330c8a42" />


**File scan** always performs local static analysis first: hashes, printable strings, embedded artifacts, local heuristics, and optional hash reputation. When an analyst selects Hybrid Analysis or Filescan.io, Cyberseek submits the sample to the selected provider for dynamic evidence. The dynamic view organizes observed actions, commands, MITRE classification, threat level, network connections, AI-assisted action triage, and indicators of compromise in separate tabs. A local static scan does not execute the uploaded file.

<img width="1611" height="962" alt="Captura de pantalla 2026-08-21 a la(s) 12 24 35 a  m" src="https://github.com/user-attachments/assets/b7960873-09c5-4309-9f66-e20a9d7f881d" />

<img width="1599" height="898" alt="Captura de pantalla 2026-08-21 a la(s) 12 24 53 a  m" src="https://github.com/user-attachments/assets/8c288bda-ddb0-45d9-9df4-a51d7bfc8e71" />

<img width="1608" height="959" alt="Captura de pantalla 2026-08-21 a la(s) 12 25 03 a  m" src="https://github.com/user-attachments/assets/4cb7b999-d3b1-4a08-bcb1-89fcc559107e" />

<img width="1610" height="954" alt="Captura de pantalla 2026-08-21 a la(s) 12 25 19 a  m" src="https://github.com/user-attachments/assets/418da5f3-7531-42b8-8c77-8b1a14088579" />

<img width="1625" height="943" alt="Captura de pantalla 2026-08-21 a la(s) 12 25 31 a  m" src="https://github.com/user-attachments/assets/6f16fbed-fbac-4955-938a-726a0694b301" />

## Investigation workflow

1. An administrator configures only the sources that the organization is authorized to use.
2. An analyst creates a monitoring, reconnaissance, or analysis task and chooses whether it is private.
3. Cyberseek records the task, gathers the permitted evidence, and updates the status while background work completes.
4. The analyst reviews source verdicts, extracted indicators, map or network context, local correlations, and MITRE mappings.
5. The analyst exports the task or IoCs and validates the finding against organizational telemetry before making a disposition.

## Local data and privacy

- Core task metadata, local correlations, source results, and user accounts are held in `instance/cyberseek.db`.
- Uploaded files are stored under `uploads/`; Live URL screenshots are stored under `instance/live_url_captures/`.
- An external dynamic provider receives a file only when the analyst explicitly selects Dynamic analysis and chooses a provider.
- Two-factor secrets are encrypted in the local database; retain `instance/.two_factor.key` with the local application data.
- Source API keys and AI settings are held in the local `config.ini` file.

## Security controls

- Mandatory login with a default `admin` / `arasaka` account that must change its password on first use.
- Optional per-user TOTP two-factor authentication with a QR setup flow compatible with standard authenticator apps. Enabled accounts require a six-digit code after password verification.
- CSRF protection on application forms and secure session settings configurable through `config.ini`.
- Failed sign-in protection quarantines an IP after repeated failures and increases the quarantine interval for recurring attempts.
- Private, loopback, link-local, and reserved network destinations are rejected by relevant reconnaissance and analysis modules.

## Local installation

Package installation with `setup.py`:

```bash
sudo python3 setup.py install
```

The Linux service configuration is created at `/var/lib/cyberseek/config.ini` during installation. Existing configuration is preserved when the installer is run again.

To update only the application Python files, templates, and interface assets while preserving `/var/lib/cyberseek/config.ini`, the SQLite database, uploads, and browser cache:

```bash
sudo python3 setup.py update
```

The command copies the current application files into the existing private runtime and restarts the Cyberseek service. It does not reinstall dependencies or modify stored data.

To remove Cyberseek completely, including its installed package, automatic-start service, local database, uploads, screenshots, `.env`, and `config.ini`:

```bash
sudo python3 setup.py uninstall
```

Open `http://127.0.0.1:3000`, sign in, and change its password immediately.

## Service configuration

The optional `[service]` section in `config.ini` configures the local listener and session behavior:

```ini
[service]
PERMANENT_SESSION_LIFETIME = 10
INTERFACE = 127.0.0.1
PORT = 3000
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = Lax
WTF_CSRF_SSL_STRICT = False
```

`PERMANENT_SESSION_LIFETIME` is expressed in minutes. For an HTTPS deployment, enable `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `WTF_CSRF_SSL_STRICT`. Forwarded client-IP headers are trusted automatically and exclusively when the direct connection is from `127.0.0.1` or `::1`; otherwise they are ignored.
