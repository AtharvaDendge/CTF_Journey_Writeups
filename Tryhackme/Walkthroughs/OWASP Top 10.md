# 🛡️ OWASP Top 10 — TryHackMe Room  

<p align="center">
  <img width="200" height="200" alt="OWASP logo" src="https://owasp.org/API-Security/editions/2019/en/images/owasp-logo.png" />
</p>

<p align="center"><em>Practical walkthrough and notes from the OWASP Top 10 room on TryHackMe</em></p>

---

## 🏷️ Challenge Information
- **Title:** OWASP Top 10  
- **Platform:** TryHackMe  
- **Tags:** Web Security · OWASP · Injection · Authentication · Enumeration  
- **Difficulty:** Easy

---

## 📝 Description
Learn about and exploit each of the OWASP Top 10 vulnerabilities — the 10 most critical web security risks — through short theory sections and hands‑on tasks.

---

## 📝 Overview
This room covers the OWASP Top 10 vulnerabilities. Each module includes:
- Short theoretical overview  
- Hands‑on exploitation in a controlled lab  
- Recovery of flags / artifacts  
- Remediation recommendations

**Key topics covered:**
- Injection & Command Injection  
- Broken Authentication  
- Sensitive Data Exposure  
- XML External Entity (XXE)  
- Broken Access Control (IDOR)  
- Security Misconfiguration  
- Cross‑Site Scripting (XSS)  
- Insecure Deserialization  
- Components with Known Vulnerabilities  
- Insufficient Logging & Monitoring

---

## ⚙️ Environment Setup
- **Platform:** TryHackMe  
- **Connection:** AttackBox (browser)  
- **Notes:** All testing performed in the provided lab environment; no external scanning outside the lab scope.

---

## 🔎 Enumeration
- Explored app behavior and input handling manually.  
- No network scanning required for initial tasks since the room provides direct URLs.  
- Focused on how inputs affect responses and where sensitive files might be exposed.

---

## 🚀 Exploitation Walkthrough

<details>
 🟣 Task 3 — Injection (Theory)</summary>

- **What it is:** User input interpreted as code/queries (SQL, OS, LDAP, etc.).  
- **Learned:** SQL Injection vs OS Command Injection fundamentals.  
- **Defenses:**  
  - ✅ Input allow‑lists  
  - ✅ Parameterized queries / prepared statements  
  - ✅ Proper input sanitization / escaping  

> *No active exploitation in this task — theory only.*
</details>

<details>
 🟣 Task 4 — OS Command Injection (Theory)</summary>

- **Cause:** Server passes unsanitized input into system calls (`system()`, `exec`).  
- **Risk:** Arbitrary command execution, remote shells, data exfiltration.  
- **Mitigation:** Avoid shelling out with unsanitized input; validate and escape; use safe APIs.
</details>

<details>
 🟢 Task 5 — Command Injection (Practical)</summary>

- **Target:** `http://MACHINE_IP/evilshell.php`  
- **Behavior:** Command output is rendered in the browser (interactive).

**Enumeration & commands used**
```
whoami                # -> www-data
id                    # -> confirms uid/gid
uname -a              # -> Ubuntu 18.04.4
cat /usr/sbin/nologin # -> shows shell
ls /                  # -> found drpepper.txt
cat /etc/motd         # -> "Dr Pepper" (fun MOTD)
```
<details>
 🟢 Task 5 — Command Injection (Practical) — Key Findings</summary>

**Key findings:**
- Strange file in `/`: `drpepper.txt`
- Application user: `www-data`
- User shell: `/usr/sbin/nologin`
- OS: Ubuntu 18.04.4
- MOTD note: Dr Pepper
</details>

<details>
 🟠 Task 6 — Broken Authentication (Theory)</summary>

**What it enables:**
- Exploiting weak/guessable passwords
- Abusing predictable session tokens
- Brute‑force attacks

**Mitigations:**
- ✅ Strong password policy
- ✅ Account lockout / rate limiting
- ✅ Multi-Factor Authentication (MFA)
</details>

<details>
 🟠 Task 7 — Broken Authentication (Practical)</summary>

**Vulnerability:** Registration logic failure — leading/trailing whitespace not normalized.

**Steps:**
- Register `darren` → “already exists”
- Register `" darren"` (leading space) → successfully logged in as Darren

**Flags recovered:**
- Darren: `fe86079416a21a3c99937fea8874b667`
- Arthur: `d9ac0f7db4fda460ac3edeb75d75e16e`

**Remediation tip:** Normalize (trim) and validate usernames server-side; reject duplicate/ambiguous entries.
</details>

<details>
 🟠 Task 8 — Sensitive Data Exposure (Intro)</summary>

**Definition:** Application unintentionally exposes sensitive data (names, DoB, passwords, CC numbers, etc.).  

**Causes:** Weak/absent encryption, storage under web root, verbose errors, insecure backups.  

**Attack vectors:** MITM, direct download of files under web root, exposed backups.



🟠 Task 9 — SQLite Databases</summary>

**Observation:** Small webapps often use SQLite (single file).  

**Risk:** If the DB file is stored under web root, it can be downloaded.

**Basic SQLite enumeration:**
```
sqlite3 webapp.db
.tables
PRAGMA table_info(users);
SELECT * FROM users;
```

<details>
 🟠 Task 10 — Cracking Weak Hashes</summary>

**Issue:** Passwords stored as weak MD5 hashes.  

**Approach:** Export hashes → CrackStation or hashcat/john.  

**Example:**
```
MD5: 5f4dcc3b5aa765d61d8327deb882cf99 -> Password: password
```

🟠 Task 11 — Sensitive Data Exposure (Practical)</summary>

**Steps:**
- Developer note points to `/assets`
- Downloaded `webapp.db` → inspect via `sqlite3`
- Found admin hash: `6eea9b7ef19179a06954edd0f6c05ceb`
- Cracked hash → `qwertyuiop` → logged in as admin

**Flag:**
```
THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}
```

<details>
 🟠 Takeaway — Sensitive Data Exposure</summary>

**Key Takeaways:**
- 🚫 Don’t place DB files under web-accessible directories  
- 🔐 Use strong salted hashes (bcrypt / Argon2)  
- 🗄️ Encrypt sensitive data at rest
</details>

<details>
 🟢 Task 12 — XML External Entity (XXE) Intro</summary>

- **XXE:** XML External Entity — abusing XML parsers to read local files, SSRF, DoS, or RCE  
- **Types:**  
  - In-band (immediate response)  
  - Out-of-band (blind)
</details>

<details>
 🟢 Task 13 — Understanding XML</summary>

- Case-sensitive, requires one root element  
- Recommended prolog:
```
<?xml version="1.0" encoding="UTF-8"?>
```


🟢 Task 14 — DTD (Document Type Definition)</summary>

- **Purpose:** Define XML structure and legal elements  
- **Directives:** `!DOCTYPE`, `!ELEMENT`, `!ENTITY`

</details>

<details>
 🟢 Task 15 — XXE Payloads</summary>

**Entity substitution example:**
```
<!DOCTYPE replace [<!ENTITY name "feast">]>
<userInfo>
  <firstName>falcon</firstName>
  <lastName>&name;</lastName>
</userInfo>
```

🟢 Task 16 — XXE (Practical)</summary>

Located user falcon in /etc/passwd

SSH key found at /home/falcon/.ssh/id_rsa (first 18 chars: MIIEogIBAAKCAQEA7)

Remediation:

Disable DTD/external entities

Validate XML input

Run web processes with least privilege

</details> <details>  🟢 Task 17 — Broken Access Control</summary>

Missing server-side authorization allows access to unauthorized resources

Exploit: Force-browsing protected URLs or manipulating object IDs

Mitigation: Server-side authorization checks, deny-by-default, RBAC

</details> <details>  🟢 Task 18 — IDOR (Challenge)</summary>

Pattern: Enumerate object IDs to access other users’ data

Example: http://MACHINE_IP/notes?note_id=10 → change note_id to access other notes

Flag: flag{fivefourthree}

Fix: Verify ownership server-side; use opaque IDs

</details> <details>  🟢 Task 19 — Security Misconfiguration</summary>

Scan for admin panels → try default credentials → gain access

Flag: thm{4b9513968fd564a87b28aa1f9d672e17}

Fixes: Change all default credentials, remove unused services, restrict admin access

</details> <details>  🟢 Task 20 — Cross-Site Scripting (XSS)</summary>

Types: Reflected, Stored, DOM-based

Example flags:

Reflected: alert("Hello") → ThereIsMoreToXSSThanYouThink

Stored: W3LL_D0N3_LVL2

Page title defacement: websites_can_be_easily_defaced_with_xss

Mitigation: Context-aware output encoding, CSP, HttpOnly + Secure cookies, sanitize inputs

</details> <details>  🟢 Tasks 21-26 — Insecure Deserialization</summary>

Risk: Deserializing untrusted data → DoS, logic tampering, RCE

Cookie exploitation: Change userType from user → admin

Flags:

THM{good_old_base64_huh}

THM{heres_the_admin_flag}

RCE flag: 4a69a7ff9fd68

Mitigation: Sign/validate serialized data; restrict privileges

</details> <details>  🟢 Tasks 27-29 — Components with Known Vulnerabilities</summary>

Identify software version → search exploits → adapt → execute → RCE

Lesson: Maintain SBOM, patch promptly, isolate vulnerable components

</details> <details>  🟢 Task 30 — Insufficient Logging & Monitoring</summary>

Proper logging is essential for incident detection and response

Minimum fields: timestamp, HTTP status, username, endpoint, source IP, user-agent

Observed attacker IP: 49.99.13.16

Controls: Centralize logs, alerts for anomalies, retain immutable logs

</details>
🔑 Key Flags

Darren: fe86079416a21a3c99937fea8874b667

Arthur: d9ac0f7db4fda460ac3edeb75d75e16e

Admin: THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}

IDOR: flag{fivefourthree}

Default creds: thm{4b9513968fd564a87b28aa1f9d672e17}

Cookie flags: THM{good_old_base64_huh}, THM{heres_the_admin_flag}

RCE: 4a69a7ff9fd68

✅ Lessons Learned

Never trust user input — validate, normalize, sanitize

Protect sensitive files — move DBs outside web root, enforce permissions

Use modern crypto — salted hashes (bcrypt/Argon2)

Keep components updated — monitor CVEs, patch promptly

Harden XML parsing — disable DTD/external entities, use secure parsers

Log & monitor — centralize, alert on anomalies

Apply least privilege — minimize web service permissions

🛠️ Practical Remediation Checklist

Trim & normalize inputs server-side

Move DB files outside web root; restrict permissions

Enforce password policies, rate limits, MFA

Disable XML external entities; use safe parsing libraries

Sign/verify cookies; avoid client-side serialized objects

Apply CSP; context-aware escaping for XSS

Maintain SBOM; automate patching; monitor for known CVEs

Centralize logs; alert on anomalies; retain immutable copies
