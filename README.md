# TriageMaster ⚡

> **Automated Reconnaissance Pipeline for Pentesting & Bug Bounty.**

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Reconnaissance-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

**TriageMaster** is a hardened Bash reconnaissance pipeline that automates early-stage asset discovery, service validation, and vulnerability triage using industry-standard offensive security tools.

Instead of running tools individually and manually parsing output, TriageMaster produces a structured reconnaissance workspace containing validated assets, visual evidence, exposed services, and triaged findings within minutes.
---

## 🚀 The Workflow (The Hunter's Funnel)

TriageMaster follows a strict "Funnel Methodology" to ensure no critical asset is missed:

1.  **DNS Enumeration:** Uses `Subfinder` to gather all available subdomains.
2.  **Port Discovery:** Uses `Naabu` to scan critical Web & Infrastructure ports (not just 80/443).
3.  **Smart Validation:** Uses **[ScopeSentry](https://github.com/sanmirgabriel/scopesentry)** (custom-built Go validation engine) to validate HTTP/S services, identifying Admin Panels, APIs, and Tech Stacks with smart fallback.
4.  **Historical Mining:** Uses `GAU` + `Uro` to find interesting legacy URLs and potential SQLi parameters from historical sources (Wayback, CommonCrawl, OTX).
5.  **Visual Recon:** Uses `GoWitness` to capture screenshots of all live services.
6.  **Vulnerability Scanning:** Uses `Nuclei` on live targets to identify misconfigurations, exposures, and known vulnerabilities.

---

## 📦 Requirements

You need the following tools installed and in your `$PATH`:

* [Subfinder](https://github.com/projectdiscovery/subfinder) (Passive Recon)
* [Naabu](https://github.com/projectdiscovery/naabu) (Port Scanning)
* **[ScopeSentry](https://github.com/sanmirgabriel/scopesentry)** (Active Validation & Tagging)
* [Nuclei](https://github.com/projectdiscovery/nuclei) (Vuln Scanning)
* [GAU](https://github.com/lc/gau) (Historical URL Fetching)
* [Uro](https://github.com/s0md3v/uro) (URL De-duplication)
* [GoWitness](https://github.com/sensepost/gowitness) (Screenshots)
* `jq` (JSON Processing)

### Quick Install (Kali/Linux)

```bash
# Go Tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/sensepost/gowitness@latest


# Python Tools
pip3 install uro

# System Tools
sudo apt install jq
```

*Note: Ensure you have `ScopeSentry` installed and compiled from [here](https://github.com/sanmirgabriel/scopesentry).*

---

## 🛠️ Installation

```bash
git clone https://github.com/sanmirgabriel/triagemaster.git
cd triagemaster
chmod +x triage.sh
```

---

## 🎯 Usage

Simply provide the target domain. The script handles sanitization (e.g., removing `https://`).

```bash
./triage.sh target.com
```

### Output Structure

The tool creates a workspace in `recon/target.com_DATE/`:

| File/Folder | Description |
| :--- | :--- |
| `subs_raw.txt` | All subdomains found via DNS enumeration. |
| `ports.txt` | Open ports discovered by Naabu. |
| `infra_exposed.txt` | **[CRITICAL]** Infrastructure services (SSH, FTP, RDP, DBs) exposed to the internet. |
| `alive.json` | Rich JSON data from **ScopeSentry** (Status, Title, Tech, Tags). |
| `screenshots/` | Visual proof of all live web services (GoWitness). |
| `nuclei.txt` | Potential vulnerabilities and misconfigurations found. |
| `params_sqli.txt` | Clean list of URLs with parameters (`?id=`) ready for SQLMap/Fuzzing. |

---

## 🧠 Logic & Philosophy

This tool was built to solve the **"False Negative"** problem.
Most triage scripts only check ports 80/443. **TriageMaster** checks critical infrastructure ports (like 8080, 8443, 3000, 3306) and validates them using `ScopeSentry`.

If a subdomain has no web server on port 443 but exposes a MySQL database on port 3306, TriageMaster will flag it in `infra_exposed.txt`.

---

## 📝 License

Intended for legal security research and authorized testing only.  Unauthorized testing against systems you do not own or have explicit permission to assess is illegal..

---

*Created by [Sanmir Gabriel](https://github.com/sanmirgabriel)*
