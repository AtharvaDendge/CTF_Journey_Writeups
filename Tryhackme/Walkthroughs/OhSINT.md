<p align="center">
  <img width="400" alt="image" src="https://tryhackme-images.s3.amazonaws.com/room-icons/9c6bc7e6db746ea68ecaa99e328923f1.png" />
</p>

<h1 align="center">Room: OhSINT</h1>

---

## 🏷️ Challenge Information
- **Title**: OhSINT  
- **Platform**: TryHackMe  
- **Category**: OSINT (Open Source Intelligence)  
- **Difficulty**: Easy   

---

## 🚀 Getting Started
1. Join the **OhSINT** room on TryHackMe.  
2. Download the Task Files.   

💡 **Note:** Actual pentesting begins after downloading the task image, as all subsequent investigation stems from this file.

---

## 🔎 Enumeration & Investigation

### Step 1: Inspecting the Image
We start by examining the downloaded image to see if it contains any hidden metadata.
```
exiftool image.jpg
```

* The EXIF data revealed a username: OWoodflint.

* This becomes our starting point for further OSINT searches.

Step 2: Finding the Avatar

We search the username online and discover that the profile picture used by this person is of a cat.

✅ Answer: cat

Step 3: Locating the Person’s City

From the profile’s social media information and posts, we identify that the person is based in London.

✅ Answer: London

Step 4: Identifying the WAP SSID

Further digging reveals the Wi-Fi SSID (visible in a public photo post).

✅ Answer: UnileverWiFi

Step 5: Discovering Personal Email

Looking through the username on GitHub leads us to their personal email address.

✅ Answer: OWoodflint@gmail.com

Step 6: Site Where Email Was Found

The email address was discovered specifically on GitHub.

✅ Answer: Github

Step 7: Finding the Holiday Destination

A photo posted on the profile reveals that the user went on holiday to New York.

✅ Answer: New York

Step 8: Retrieving the Password

By digging further into the publicly accessible repositories and posts, we uncover the password.

✅ Answer: pennYDr0pper.!

🏁 Answers Recap
Question	Answer
What is this user's avatar of?	cat
What city is this person in?	London
What is the SSID of the WAP he connected to?	UnileverWiFi
What is his personal email address?	OWoodflint@gmail.com
What site did you find his email address on?	Github
Where has he gone on holiday?	New York
What is the person's password?	pennYDr0pper.!

## 👨‍💻 Author

Write-up by: Atharva Dendge

Platform: TryHackMe – OhSINT Room

#### This write-up is created for educational and learning purposes to demonstrate OSINT methodology.

