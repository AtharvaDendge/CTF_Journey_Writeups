<p align="center">
  <img width="400" alt="Shodan Logo" src="https://eu-images.contentstack.com/v3/assets/blt6d90778a997de1cd/blt9d7e3e67ee22e302/64f0d52f523617f7d6948984/Image_1.jpg?disable=upscale&width=1200&height=630&fit=crop" />
</p>

<h1 align="center">Room: Shodan</h1>

---

## 🏷️ Challenge Information
- **Title**: Shodan  
- **Platform**: TryHackMe  
- **Category**: Recon / OSINT  
- **Difficulty**: Easy   

---

## 🚀 Starting Point
After joining we’re ready to start **reconnaissance and exploration** using **Shodan.io**.  
This is the point where the *actual pentesting / OSINT investigation begins*.

---

## 🕵️ Task 1: Introduction
Shodan.io is often called the **“Search Engine for the Internet of Things (IoT)”**.  
It lets us discover devices and services that are exposed to the internet, such as:
- CCTV cameras
- Industrial control systems
- Routers, databases, etc.

We’ll use Shodan to:
- Identify IPs
- Explore open ports
- Investigate banners that reveal device/service details

---

## 🧩 Task 1 Questions & Answers
- **Q:** What is this user's avatar of?  
  **A:** `cat`  

- **Q:** What city is this person in?  
  **A:** `London`  

- **Q:** What is the SSID of the WAP he connected to?  
  **A:** `UnileverWiFi`  

- **Q:** What is his personal email address?  
  **A:** `OWoodflint@gmail.com`  

- **Q:** What site did you find his email address on?  
  **A:** `GitHub`  

- **Q:** Where has he gone on holiday?  
  **A:** `New York`  

- **Q:** What is the person's password?  
  **A:** `pennYDr0pper.!`  

---

## 📡 Task 2: Filters
Shodan supports powerful **filters** to refine searches.  
Example filters:
```
text

product:MySQL
asn:AS14061
vuln:ms17-010
```
We can combine them for specific queries:
```asn:AS14061 product:MySQL```
👉 This allows us to discover MySQL servers on the specified ASN.

✅ Task 2 Question

Q: What command is used to find Eternal Blue exploits on Shodan using the vuln filter?
A: vuln:ms17-010

🌍 Task 3: Google & Filtering

We leverage Google ASN + Shodan filters to gather more insights.

Q: Top OS for MySQL servers in Google’s ASN → 5.6.40-84.0-log

Q: 2nd most popular country for MySQL servers in Google’s ASN → Netherlands

Q: For nginx under Google’s ASN → Hypertext Transfer Protocol

Q: Most popular city under Google’s ASN → Kansas City

Q: Top OS in Los Angeles under Google’s ASN → Debian

Q: Using top webcam search in Explore page, does Google’s ASN have webcams? → Nay

📊 Task 4: Shodan Monitor

Shodan Monitor provides:

Top Open Ports

Top Vulnerabilities

Notable IPs

Potential Risks

👉 URL to access:
https://monitor.shodan.io/dashboard

🔎 Task 5: Shodan Dorking

Some useful Shodan dorks:
```
has_screenshot:true encrypted attention    # PCs infected by Ransomware
screenshot.label:ics                        # Industrial Control Systems
vuln:CVE-2014-0160                           # Heartbleed-vulnerable devices
http.favicon.hash:-1776962843                # SolarWinds attack indicator
```
✅ Task 5 Answer:

Dork to find PCs infected by ransomware →
```has_screenshot:true encrypted attention```

🧩 Task 6: Shodan Extension

Shodan provides a Chrome extension:
Shodan Chrome Extension

It allows:

Quick IP & port checks

Location info

Basic vulnerability info

✅ Great for quick bug bounty reconnaissance.

🧑‍💻 Task 7: Exploring the API & Conclusion

### Shodan’s API lets us programmatically:

* Search for IPs

* Identify vulnerabilities

* Monitor networks

### 🏁 Key Takeaways

* Shodan is a powerful OSINT & recon tool.

* ASN-based searches help find services across an organization’s entire network.

* Filters & dorks make searches precise and impactful.

* Shodan Monitor & API enhance ongoing security assessments.

## 👨‍💻 Author

### Atharva Balasaheb Dendge

•	GitHub: https://github.com/AtharvaDendge

•	LinkedIn: https://www.linkedin.com/in/atharva-balasaheb-dendge/


