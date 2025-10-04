WASP Top 10 — TryHackMe Room
<p align="center"> <img width="200" height="200" alt="OWASP logo" src="https://owasp.org/API-Security/editions/2019/en/images/owasp-logo.png" /> </p> <p align="center"><em>Practical walkthrough and notes from the OWASP Top 10 room on TryHackMe</em></p>
🏷️ Challenge Snapshot

Title: OWASP Top 10

Platform: TryHackMe

Tags: Web Security · OWASP · Injection · Authentication · Enumeration

Difficulty: Easy

Summary / Objective

This room teaches the OWASP Top 10 web security risks by combining short theory sections with hands‑on challenges. For each vulnerability I reviewed the concepts, performed safe lab exploitation, captured relevant flags, and documented remediation advice.

All work was performed in the provided TryHackMe lab environment using the browser AttackBox. No external targeting or scanning beyond the lab scope was performed.

Environment

Platform: TryHackMe

Connection: AttackBox (browser)

Lab conditions: Controlled, intentionally vulnerable web applications and services

Enumeration notes

The room supplies target URLs for each task, so initial discovery was manual exploration and input probing rather than network scanning. I focused on understanding the application behavior and how each vulnerability manifests.

Exploitation walkthrough (tasks & findings)
Task 3 — Injection (concept)

What I learned: Injection happens when user input is interpreted as code or queries (SQL, OS commands, etc.).
Defense highlights: input allow‑lists, proper sanitization/escaping, parameterized queries.
(Task was theoretical in this section.)

Task 4 — OS Command Injection (concept)

What I learned: Server code that forwards unsanitized input to system calls can allow arbitrary command execution or reverse shells. Validate and sanitize inputs; never pass raw user input into shell calls.

Task 5 — Command Injection (practical)

Target: http://MACHINE_IP/evilshell.php — command responses render in the browser.

Key commands and outputs I used:

whoami          # www-data
id              # confirms uid/gid
uname -a        # Ubuntu 18.04.4
cat /usr/sbin/nologin
ls /
cat /etc/motd   # contains a whimsical note


Findings

App user: www-data

OS: Ubuntu 18.04.4

Interesting file in /: drpepper.txt

MOTD message: Dr Pepper

Task 6 — Broken Authentication (concept)

Risks: weak/guessable passwords, predictable session tokens, logic flaws in registration/login.
Mitigations: strong password policies, rate limiting/lockouts, multi‑factor authentication.

Task 7 — Broken Authentication (practical)

Vulnerability: registration logic allowed username collisions via leading/trailing whitespace.

Steps

Registering darren → “already exists.”

Registering " darren" (leading space) → logged in as Darren.

Flags recovered

Darren: fe86079416a21a3c99937fea8874b667

Arthur: d9ac0f7db4fda460ac3edeb75d75e16e

Takeaway: Normalize and validate usernames server‑side (trim, reject unicode tricks).

Task 8–11 — Sensitive Data Exposure (intro → DB extraction → cracking)

Issue: Flat‑file DB stored under web root and weak password hashes (MD5).

Process

Found /assets/webapp.db.

Downloaded DB and explored with sqlite3:

.tables
PRAGMA table_info(users);
SELECT * FROM users;


Cracked MD5 hashes (e.g., 5f4dcc3b5aa765d61d8327deb882cf99 → password).

Admin compromise

Admin hash: 6eea9b7ef19179a06954edd0f6c05ceb → cracked to qwertyuiop → logged in.

Flag: THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}

Remediations

Never expose DB files under web‑accessible directories.

Use strong salted hashing (bcrypt / Argon2), encrypt sensitive data at rest, and apply least privilege to filesystem permissions.

Task 12–16 — XML External Entity (XXE)

Concept: XXE lets an attacker abuse XML parsers to read local files, make SSRF requests, or cause DoS/RCE.

Key examples

In‑band vs out‑of‑band XXE.

Example payload to read /etc/passwd:

<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM "file:///etc/passwd">]>
<root>&read;</root>


Findings from lab

Located falcon user in /etc/passwd.

SSH key at /home/falcon/.ssh/id_rsa — first 18 chars observed: MIIEogIBAAKCAQEA7.

Fixes

Disable external entity resolution or use safe parsers (e.g., defusedxml), validate XML input, run web processes with minimal privileges.

Task 17–18 — Broken Access Control & IDOR

Broken access control: force‑browsing and missing server‑side authorization checks allow resource exposure.

IDOR example

URL: http://MACHINE_IP/notes?note_id=10 → change note_id values to enumerate other users' notes.

Found note with flag: flag{fivefourthree}

Mitigation

Enforce ownership checks, use opaque/non‑predictable IDs, implement deny‑by‑default authorization.

Task 19 — Security Misconfiguration (default credentials)

Attack: scanned for admin panels and tried default creds → succeeded.
Flag: thm{4b9513968fd564a87b28aa1f9d672e17}

Fixes

Change default passwords, disable unused services, restrict admin interfaces (IP allow‑lists / VPN), remove verbose errors.

Task 20 — Cross‑Site Scripting (XSS)

Types covered: DOM, Reflected, Stored.

Examples & outcomes

Reflected payload: <script>alert("Hello")</script> → token: ThereIsMoreToXSSThanYouThink

Stored XSS: injected JS that calls alert(document.cookie) → flags and page defacement strings (e.g., W3LL_D0N3_LVL2, websites_can_be_easily_defaced_with_xss).

Mitigation

Context‑aware escaping/encoding, CSP, HttpOnly/Secure cookies, input validation.

Task 21–26 — Insecure Deserialization (theory → cookies → RCE)

Summary

Deserializing untrusted data (e.g., Python pickle) can lead to logic manipulation, DoS, or RCE.

Cookies were used to store serialized objects in the lab.

Practical steps

Inspected cookies, found base64/encoded payloads.

Modified userType cookie from user → admin to access admin dashboard flags:

Cookie flag: THM{good_old_base64_huh}

Admin flag: THM{heres_the_admin_flag}

RCE

Created Python pickle payload, base64 encoded it into encodedPayload cookie, run a netcat listener → received reverse shell.

Flag in flag.txt: 4a69a7ff9fd68

Defenses

Avoid deserializing untrusted data. If necessary, sign/verify serialized blobs, or use safe formats (JSON) and strict parsing. Run deserialization code with strict privileges.

Task 27–29 — Components with Known Vulnerabilities

Concept: Using outdated components (e.g., Nostromo 1.9.6) is a common and easily exploitable risk.

Approach

Enumerate service/version → search Exploit‑DB / advisories → adapt public exploit → execute → RCE.

Lesson

Maintain SBOM, track CVEs, apply vendor patches promptly, and isolate risky components.

Task 30 — Insufficient Logging & Monitoring

Why it matters: Without logs and monitoring you can’t detect or reconstruct attacks.

Recommended minimum fields

Timestamps (with timezone), HTTP status codes, usernames, requested endpoints, source IPs, user-agent, etc.

Exercise

Analyzed sample logs, found brute‑force attacker IP: 49.99.13.16.

Controls

Centralize logs (SIEM), protect integrity, create alerts for high‑impact signals (multiple failed logins, unusual geolocations), and retain immutable copies for incident response.

Key flags & artifacts (quick list)

Darren: fe86079416a21a3c99937fea8874b667

Arthur: d9ac0f7db4fda460ac3edeb75d75e16e

Admin (sensitive DB exploit): THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}

IDOR flag: flag{fivefourthree}

Default password flag: thm{4b9513968fd564a87b28aa1f9d672e17}

Cookie flags: THM{good_old_base64_huh}, THM{heres_the_admin_flag}

Insecure deserialization RCE flag: 4a69a7ff9fd68

Lessons learned (short)

Never trust user input. Validate, sanitize, and use allow‑lists.

Secure sensitive files. Don’t store DB files under web root; correct filesystem permissions.

Use modern crypto. Salt + strong hashing (bcrypt/Argon2) and encryption at rest.

Keep components updated. Track dependencies, patch promptly, maintain SBOM.

Harden XML handling. Disable DTD/external entities or use secure parsers.

Log and monitor. Proper logging + alerting dramatically shortens detection time.

Principle of least privilege. Reduce attacker blast radius (process, file, network).

Practical remediation checklist (actionable)

Trim and normalize usernames on registration; apply server‑side validation.

Move DB files out of web root and enforce strict file permissions.

Enforce MFA and account lockouts; implement rate limiting.

Disable XML external entity resolution and use safe XML libs.

Set cookies with HttpOnly, Secure, SameSite; sign serialized data.

Apply CSP and escape output context‑appropriately for XSS.

Maintain an inventory of components and subscribe to CVE notifications.

Centralize logs, configure alerts for brute force and privilege escalation patterns.

Final thoughts (personal)

This room is an excellent practical survey of the OWASP Top 10: each module pairs compact theory with realistic lab exercises that reinforce the concepts. The hands‑on tasks made it easy to connect defensive best practices to concrete attack techniques. For anyone taking their first steps into web application security, this is a highly recommended, well‑structured lab.

If you want, I can:

Convert this into a one‑page PDF or slide deck for your portfolio.

Produce a short checklist poster you can pin by your desk.
Which would you prefer?
