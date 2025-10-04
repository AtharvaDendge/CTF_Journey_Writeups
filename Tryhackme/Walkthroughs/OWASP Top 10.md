<p align="center">
  <img width="400" height="400" alt="image" src="https://owasp.org/API-Security/editions/2019/en/images/owasp-logo.png" />
</p>
<h1 align="center">Room: Owasp Top 10</h1>

## 🏷️ Challenge Information
- **Title**: Owasp Top 10
- **Platform**: TryHackMe
- **Tags**: Web Security, OWASP, Injection, Authentication, Enumeration
- **Difficulty**: Easy

________________________________________
📝 Description

Learn about and exploit each of the OWASP Top 10 vulnerabilities; the 10 most critical web security risks.

---

📝 Overview

This room covers the OWASP Top 10 vulnerabilities.
We learn each vulnerability theoretically and then exploit it through hands-on challenges.

Key topics:

Injection & Command Injection

Broken Authentication

Sensitive Data Exposure

XXE

Broken Access Control

Security Misconfiguration

XSS

Insecure Deserialization

Components with Known Vulnerabilities

Insufficient Logging & Monitoring

⚙️ Environment Setup

Platform: TryHackMe

Connection: Used AttackBox in browser

All exploits were performed in a safe, controlled lab environment.

🔎 Enumeration

Before exploiting, I explored how each vulnerability behaves.
No scanning was required for initial tasks as the room provides direct target URLs.

🚀 Exploitation Walkthrough
Task 3 – Injection

Injection flaws occur when user-supplied input is interpreted as commands or queries.

Learned about SQL Injection and Command Injection.

Defense includes using:

Input allow-lists

Input sanitization or stripping dangerous characters

No active exploitation in this task — only theory.

Task 4 – OS Command Injection

Understanding Command Injection:

Happens when server-side code (e.g., PHP) passes unsanitized input to system calls.

Could allow attackers to execute arbitrary OS commands or even spawn a reverse shell.

Task 5 – Command Injection Practical

Connected to:
http://MACHINE_IP/evilshell.php

Here, active command injection was present — meaning the response of executed commands was visible in the browser.

Steps & Findings:

```
# Enumerating
whoami                 # Revealed user: www-data
id                     # Confirmed privileges
uname -a               # Revealed Ubuntu 18.04.4
cat /usr/sbin/nologin  # Verified user's shell
ls /                   # Found interesting file: drpepper.txt
cat /etc/motd          # Discovered favorite beverage: Dr Pepper
```

Key Answers:

Strange text file in root: drpepper.txt

Non-root/non-service/non-daemon users: 0

App running as: www-data

User’s shell: /usr/sbin/nologin

OS version: Ubuntu 18.04.4

Favorite beverage in MOTD: Dr Pepper

Task 6 – Broken Authentication

Understood how flaws in authentication mechanisms allow attackers to:

Exploit weak or guessable passwords

Abuse predictable session cookies

Perform brute-force attacks

Defenses:

Strong password policies

Lockout after failed attempts

Enforcing Multi-Factor Authentication (MFA)

Task 7 – Broken Authentication Practical

The app was vulnerable to logic flaw in registration.

Steps:

Tried registering username darren → “already exists”.

Registered " darren" (with a leading space) → logged in successfully as Darren.

Retrieved flag from Darren’s account.

Flag (Darren): ``` fe86079416a21a3c99937fea8874b667 ```

Repeated same technique for arthur and retrieved:

Flag (Arthur): ``` d9ac0f7db4fda460ac3edeb75d75e16e ```

🟠 Task 8 – Sensitive Data Exposure (Intro)

When a web application unintentionally leaks sensitive data (like names, DoB, passwords, credit card numbers, etc.), it’s called Sensitive Data Exposure.

Can happen due to weak encryption, or even by storing data in accessible web directories.

Sometimes exploited via MITM (Man-in-the-Middle) attacks.

In this challenge, the vulnerability came from improper handling of a flat-file database.

🟠 Task 9 – SQLite Databases

Many small webapps use SQLite flat-file databases instead of a full DB server.
If the database file is stored under the web root, an attacker can simply download it.

Basic enumeration in Kali: 

```
sqlite3 webapp.db          # open the database
.tables                    # list tables
PRAGMA table_info(users);  # view schema
SELECT * FROM users;       # dump data
```
🟠 Task 10 – Cracking Weak Hashes

Passwords in the DB were stored as weak MD5 hashes.

Used CrackStation
 to recover plaintext credentials.

Example:
Hash: 5f4dcc3b5aa765d61d8327deb882cf99 → Password: password

🟠 Task 11 – Sensitive Data Exposure Challenge

Steps:

Explored webapp → found developer’s note pointing to /assets.

Navigated to /assets → located webapp.db.

Downloaded the DB and inspected using sqlite3.

Found admin hash: ```6eea9b7ef19179a06954edd0f6c05ceb```

Cracked hash using CrackStation → Password: qwertyuiop

Logged in as admin.

Flag: ```THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}```

🔑 Lessons Learned

Never store sensitive DB files under web-accessible directories.

Always hash + salt passwords using strong algorithms (e.g., bcrypt, Argon2).

Encrypt sensitive data at rest.

Apply the principle of least privilege to files and directories.

🟢 Task 12 – XML External Entity (XXE) Intro

XXE abuses XML parsers to:

Read local files

Make SSRF requests

Sometimes lead to DoS or RCE

Two types:

In-band: attacker gets immediate response in the app.

Out-of-band (blind): attacker exfiltrates data indirectly (e.g., via external server).

🟢 Task 13 – Understanding XML

XML = eXtensible Markup Language

Stores & transports data in a platform-independent way.

Optional but recommended XML prolog: ```<?xml version="1.0" encoding="UTF-8"?>```

Requires a single ROOT element.

Case-sensitive and allows attributes.

🟢 Task 14 – DTD (Document Type Definition)

DTD defines structure & legal elements of XML.

Example: 
```
<!DOCTYPE note [
    <!ELEMENT note (to,from,heading,body)>
    <!ELEMENT to (#PCDATA)>
    <!ELEMENT from (#PCDATA)>
    <!ELEMENT heading (#PCDATA)>
    <!ELEMENT body (#PCDATA)>
]>
```

Important directives:

!DOCTYPE → defines root

!ELEMENT → defines elements

!ENTITY → defines reusable values or external references

🟢 Task 15 – XXE Payloads

Basic ENTITY substitution:

<!DOCTYPE replace [<!ENTITY name "feast">]>
<userInfo>
    <firstName>falcon</firstName>
    <lastName>&name;</lastName>
</userInfo>


Reading local files:

<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM "file:///etc/passwd">]>
<root>&read;</root>


If vulnerable, app displays contents of /etc/passwd.

⚠️ Key Takeaways from XXE

Disable external entity resolution in XML parsers.

Use libraries that automatically protect against XXE (e.g., defusedxml in Python).

Sanitize & validate all XML input before parsing.

🟢 Task 16 – XML External Entity (XXE) — Exploitation

XXE allows an attacker to make an XML parser resolve external entities (files, URLs), disclosing local resources or injecting content.

Example — verify injection (entity substitution):

```
<?xml version="1.0"?>
<!DOCTYPE root [
    <!ENTITY name "falcon feast">
]>
<root>
    <greeting>&name;</greeting>
</root>
```

Example — read local file (/etc/passwd):
```
<?xml version="1.0"?>
<!DOCTYPE root [
    <!ENTITY read SYSTEM "file:///etc/passwd">
]>
<root>&read;</root>
```

Findings (from the VM):

Username in /etc/passwd: falcon

SSH key location: /home/falcon/.ssh/id_rsa

First 18 chars of falcon’s private key: MIIEogIBAAKCAQEA7

Remediation:

Disable DTDs / external entity resolution in XML parsers.

Use safe XML libraries / secure parsing modes.

Apply input validation, least privilege for web process, and avoid exposing sensitive files.

🟢 Task 17 – Broken Access Control (Concept)

Broken access control = users can access pages/resources they shouldn’t. Common causes:

Missing server-side authorization checks

Force‑browsing protected URLs

Using client-side controls as the only restriction

Example (force-browse):

http://example.com/app/admin_getappInfo   ← admin-only but accessible

Mitigations:

Enforce authorization server-side on every request.

Deny-by-default, role-based access control (RBAC).

Log and monitor suspicious access patterns.

🟢 Task 18 – IDOR (Insecure Direct Object Reference) — Challenge

IDOR: attacker manipulates object references (IDs) to access others’ resources.

Example (URL parameter enumeration):
```
http://MACHINE_IP/notes?note_id=10
→ change note_id=11,12,... to access other users' notes
```

What I did:

Logged in as noot / test1234

Enumerated note IDs and found another user’s note containing the flag

Flag:

```flag{fivefourthree}```


Remediation:

Verify resource ownership server-side before returning data.

Use opaque/non-predictable IDs and implement strict authorization checks.

🟢 Task 19 – Security Misconfiguration (Default Passwords) — Challenge

Security misconfiguration includes leaving default credentials or services enabled.

Attack pattern:

Scan for admin panels / services

Try known default username/password pairs

Result:

Found service with default creds → accessed webapp → retrieved flag

Flag:

```thm{4b9513968fd564a87b28aa1f9d672e17}```


Remediation:

Change all default passwords, enforce strong password policies.

Disable unused services; restrict admin interfaces (VPN/IP allowlist).

Harden configurations and remove verbose error messages.

🟢 Task 20 – Cross‑Site Scripting (XSS) — DOM / Reflected / Stored

XSS happens when user input is included in pages without proper encoding.

Reflected XSS example (simple popup):

```<script>alert("Hello")</script>```


Reflected challenge tokens:

Popup with "Hello" → ThereIsMoreToXSSThanYouThink

Popup with machine IP → ReflectiveXss4TheWin

Stored XSS example (comment containing script):
```
<!-- comment input -->
<script>
  alert(document.cookie);
</script>
```

Stored challenge tokens / results:

Insert raw HTML tags → HTML_T4gs

alert(document.cookie) popup → W3LL_D0N3_LVL2

Page title changed to "I am a hacker" via injected JS → websites_can_be_easily_defaced_with_xss

Remediation:

Context-aware output encoding/escaping (HTML, attribute, JS, URL contexts).

Use Content Security Policy (CSP).

Set cookies to HttpOnly and Secure; sanitize inputs where appropriate.

🟢 Task 21 – Insecure Deserialization — Overview / Quiz

Insecure deserialization: untrusted serialized data is deserialized and abused to alter logic, crash services, or achieve RCE.

Risks:

Denial of Service (crash services)

Remote Code Execution (language/framework dependent)

Business-logic tampering

Quiz answers:

Who developed Tomcat? → The Apache Software Foundation

Attack that can crash services via insecure deserialization? → Denial of Service

Remediation:

Avoid deserializing untrusted data; prefer safe formats (JSON) with strict parsing.

Use integrity checks (signatures/MACs) on serialized blobs.

Apply least privilege to deserialization contexts and monitor for anomalies.

🟢 Task 22 – Insecure Deserialization: Objects

Objects in programming (OOP) consist of:

State → Attributes or properties

Behaviour → Methods or actions

Example: A lamp object can have a type of bulb (state) and can be turned on/off (behaviour). Methods allow changing state or behaviour without rewriting the code.

Quiz answer:

If a dog was sleeping, is this State or Behaviour? → Behaviour ✅

🟢 Task 23 – Insecure Deserialization: Serialization/Deserialization

Serialization converts objects into simpler, transportable formats (e.g., binary) to send between systems.
Deserialization converts that simple data back into an object the application can process.

Example analogy: Drawing a map for a tourist → serialized info; tourist interprets it → deserialized info.

Quiz answer:

What base-2 format is used to transmit data across networks? → Binary ✅

Insecure deserialization: Occurs when untrusted data is deserialized without validation, allowing execution of malicious payloads.

🟢 Task 24 – Insecure Deserialization: Cookies

Cookies 101:

Tiny pieces of data stored in the browser by websites.

Can store session IDs, user preferences, login info, etc.

Some cookies expire on browser close; others persist via the Expiry attribute.

Cookie attributes:

Attribute	Description	Required?
Name	Cookie identifier	Yes
Value	Content (plaintext or encoded)	Yes
Secure	Sent only over HTTPS	No
Expiry	Auto-delete timestamp	No
Path	URL scope for the cookie	No

Example (Python Flask):

```
from flask import Flask, make_response
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def set_cookie():
    timestamp = datetime.now().isoformat()
    resp = make_response("Cookie Set")
    resp.set_cookie("registrationTimestamp", timestamp)
    return resp

```

Quiz answers:

Cookie path /login → user visits webapp.com/login ✅

Secure cookies work over → HTTPS ✅

🟢 Task 25 – Insecure Deserialization: Cookies Practical

Steps:

Open http://MACHINE_IP in browser and create an account.

Inspect cookies via browser developer tools (Storage tab).

Observe encoded and base64 cookies; the first flag is inside a cookie.

Modify userType cookie from user → admin.

Navigate to http://MACHINE_IP/admin for second flag.

Flags obtained:

1st cookie flag → THM{good_old_base64_huh} ✅

Admin dashboard flag → THM{heres_the_admin_flag} ✅

🟢 Task 26 – Insecure Deserialization: Code Execution

Setup / Exploit:

Change userType cookie back to user.

Visit feedback forms (“Exchange your vim” → “Provide your feedback”).

Flask app deserializes the encoded cookie using pickle.loads, trusting the user data.

Prepare a Python payload (rce.py) with base64-encoded reverse shell commands.

Run netcat listener on your Kali machine.

Paste the encoded payload into the encodedPayload cookie.

Refresh page → receive reverse shell to VM.

Flag found in flag.txt:

```4a69a7ff9fd68```


Remediation:

Never deserialize untrusted input.

Use signed or validated serialized data.

Restrict execution context and permissions for deserialization.

🟢 Task 27 – Components With Known Vulnerabilities: Intro

Many systems use software with well-known vulnerabilities (e.g., outdated WordPress). Attackers can find exploits with minimal effort.

Key points:

Prevalence is high; easy for companies to miss updates.

Exploit-db and security advisories can be used to research existing vulnerabilities.

No quiz answer required. ✅

🟢 Task 28 – Components With Known Vulnerabilities: Exploit

Example: Nostromo 1.9.6 web server.

Steps:

Identify server software & version → Nostromo 1.9.6.

Research exploits on exploit-db for that version.

Download and review the exploit script. Modify minor issues if necessary (e.g., comment out buggy lines).

Execute script → achieve RCE.

Lessons learned:

Known vulnerabilities save attackers time; always check software versions.

Reading and understanding the exploit code helps tailor it to your target.

Version enumeration + exploit-db research is a critical skill for penetration testers.

No quiz answer required. ✅

🟢 Task 29 – Components With Known Vulnerabilities: Lab

This lab is a practical exercise in finding and using a public exploit for a purposely vulnerable application. All information required (vulnerable app name/version and exploit) can be discovered via public sources (exploit-db, GitHub, vendor advisories, etc.).
Tip from the task: when running exploit scripts that accept arguments, quote your inputs (e.g. "id").

What I did:

Enumerated the service to identify the software and version.

Located the matching exploit script online.

Carefully reviewed the script, quoted input arguments as instructed, and executed it against the VM.

Useful command (to count characters in a file on the target once you have shell access):
```
wc -c /etc/passwd
# -> 1611
```

Result:

Number of characters in /etc/passwd:

```1611```


Remediation:

Keep third‑party components up to date; apply vendor patches promptly.

Maintain an inventory of components (SBOM) and monitor for known CVEs.

Restrict exposure of vulnerable services (network ACLs, firewalls) and segment critical assets.

🟢 Task 30 – Insufficient Logging & Monitoring

This task explains why thorough logging and active monitoring are critical for detecting/responding to incidents.

Key logging recommendations (minimum fields to capture):

HTTP status codes

Time stamps (with timezone)

Usernames / authenticated identifiers

API endpoints / requested URLs

Source IP addresses

User-Agent and other headers useful for detecting automation

What I did (log analysis exercise):

Inspected provided sample logs and located anomalous behavior.

Identified the attacker IP:

```49.99.13.16```


Classified the activity: Brute Force (repeated authentication attempts / repeated requests to login endpoints).

Why this matters:

Without logs, you cannot reconstruct an attacker’s actions or determine scope of compromise.

Without monitoring/alerting on high‑impact signals (multiple failed logins, logins from unusual IPs, known bad user-agents), intrusions can go unnoticed for long periods.

Remediations & controls:

Centralize logs (SIEM or log aggregator), protect log integrity and retention.

Create alerts for high‑severity patterns: multiple failed logins, rapid request rates, access from anomalous geolocations, and known exploit signatures.

Maintain separate, immutable copies of logs for incident response and compliance.

Apply rate limits, account lockout policies, and multi-factor authentication to reduce brute-force risk.
