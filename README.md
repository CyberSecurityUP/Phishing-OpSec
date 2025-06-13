## ** OPSEC Checklist for Phishing Campaigns (Red Team / Awareness Use Only)**

---

###  **1. Personal OPSEC & Anonymity**

* [ ] Use a hardened virtual machine or disposable OS (e.g., Tails, Whonix).
* [ ] Never use personal email, IP address, or identity.
* [ ] Route all traffic through VPN or Tor (never your home/work IP).
* [ ] Use burner accounts for purchasing domains/VPS (use ProtonMail, Tuta.io, etc.).
* [ ] Pay anonymously using cryptocurrencies (preferably Monero or privacy-enhanced Bitcoin wallets).

---

###  **2. Domain & DNS Hygiene**

* [ ] Register your domain through offshore providers that accept crypto and support WHOIS privacy.
* [ ] Use realistic typosquatting or homograph domain (e.g., `microsoft-updates[.]com`).
* [ ] Setup SPF/DKIM/DMARC if you plan to send emails.
* [ ] Avoid domains with previous SafeBrowsing or PhishTank reports (check via [urlscan.io](https://urlscan.io), [VirusTotal](https://virustotal.com)).

---

###  **3. Hosting & Server Configuration**

* [ ] Rent a VPS from providers outside your legal jurisdiction.
* [ ] Ensure no logs, disable SSH root login, use public-key authentication.
* [ ] Harden the server (fail2ban, ufw, disable unused services).
* [ ] Use CDN or reverse proxy (e.g., Cloudflare, DDoS Guard) to mask origin IP.
* [ ] Use temporary or rotating infrastructure for campaigns (burner VPS).

---

###  **4. TLS/SSL Best Practices**

* [ ] Issue free SSL cert via Let’s Encrypt (`certbot` or `acme.sh`).
* [ ] Avoid expired or self-signed certs.
* [ ] Ensure no mixed-content errors (all assets HTTPS).
* [ ] Scan site using [SSLLabs](https://www.ssllabs.com/ssltest/) to verify secure setup.

---

###  **5. Landing Page OPSEC**

* [ ] Clone target page accurately (e.g., login portals, Microsoft 365, Google).
* [ ] Sanitize JavaScript and external calls — remove analytics, tracking, or API links.
* [ ] Host all scripts/assets locally (no calls to real domains).
* [ ] Implement fake CAPTCHA, pastejack, or MFA intercept (e.g., Evilginx).
* [ ] Set page to redirect to legit site after login to avoid suspicion.

---

###  **6. Delivery Channel Precautions**

* [ ] Craft realistic emails or messages using templates from phishing kits or Red Team experience.
* [ ] Avoid trigger words like “urgent”, “password”, “verify now” in body or subject line.
* [ ] Use shortened links or custom redirector (kutt.it, your own URL shortener).
* [ ] Validate SafeBrowsing status of link before sending.

---

###  **7. Testing and Evasion Techniques**

* [ ] Run tests on isolated machines (sandbox) before deployment.
* [ ] Check phishing page using:

  * Google SafeBrowsing
  * VirusTotal (don’t upload directly)
  * urlscan.io (private mode)
* [ ] Use user-agent filtering or bot detection to block scanners.
* [ ] Add delay timers or human-interaction JS triggers (e.g., click-to-load credential form).

---

###  **8. Data Capture & Storage**

* [ ] Save credentials in a secure, local-only file (`usernames.txt`, encrypted storage).
* [ ] Obfuscate form fields (e.g., base64-encode or split variables).
* [ ] Avoid logging victim IPs unless anonymized.
* [ ] Use webhook only if routed through anonymity-safe proxy.

---

###  **9. Avoiding Detection and Blacklisting**

* [ ] Obfuscate JS code and forms.
* [ ] Avoid common phishing signatures in source code.
* [ ] Regularly rotate infrastructure (IP, domain, hosting).
* [ ] Use browser fingerprinting tools (e.g., WhoTargetsMe-style JS) only if needed.

---

###  **10. Campaign Tracking & Redirection**

* [ ] Append UTM or hashed campaign tokens to links for per-user tracking.
* [ ] After capture, redirect to legitimate site (e.g., real Microsoft login).
* [ ] Optionally validate captured credentials via passive login attempt (careful with ethics/legal boundaries).

---

###  **11. Cleanup & Evidence Handling**

* [ ] Delete all server logs or rotate securely.
* [ ] Shut down VPS after operation.
* [ ] Archive reports securely; never reuse credential data in real-world contexts.
* [ ] Ensure screenshots and data used for reports blur or redact sensitive info.

---

##  **Advanced OPSEC Practices (Optional)**

* [ ] Implement HTML smuggling to deliver payloads via phishing (for advanced red team).
* [ ] Use cloaking: redirect to real site if referrer is Google, AV, or crawler.
* [ ] Deploy MFA-bypass (Evilginx2) for credential + token capture.
* [ ] Monitor real-time access with webhook traps or encoded pixel trackers.
