<p align="center">
  <img width="400" height="400" alt="image" src="hhttps://owasp.org/Top10/assets/TOP_10_logo_Final_Logo_Colour.png" />
</p>
<h1 align="center">Room: Owasp Top 10</h1>

## 🏷️ Challenge Information
- **Title**: Owasp Top 10
- **Platform**: TryHackMe
- **Tags**: Web Security, OWASP, Injection, Authentication, Enumeration
- **Difficulty**: Easy

________________________________________
📝 Description

This is a machine that allows you to practise web app hacking and privilege escalation
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
