# ConnTrack

## Introduction

**ConnTrack** is a single-file, read-only cybersecurity CLI + web-app tool, part of a 27-tool
suite built to simulate and perform real host, network and file forensics workflows — the kind a
security analyst runs day to day. Reads every TCP connection with its queues, retransmit count and timer, tracks how long each has been in its state, and says which process owns it. One Python file, a CLI and a 5-page web app, SQLite history, SVG visuals.

👨‍💻 **Built by Karanam Shrivasta**
💡 Cyber Security | DFIR Enthusiast | Future Ethical Hacker

## 🌍 What Problem This Solves

Most security tooling is either:

* A paid, closed-source enterprise product
* A scattered pile of shell one-liners with no history or reporting
* Hard to audit, since you can't read the whole tool in one sitting

👉 **ConnTrack** solves this by shipping as **one readable Python file** — CLI and web app together,
no hidden network calls, no telemetry, and a `selftest` command that proves every claim above
against a temporary database before you ever point it at your own machine.

## 💡 Core Concept

Instead of scattered, one-shot scripts:

💥 **ConnTrack** uses a scan → store → score → report model

* Every scan is saved to SQLite, so you can compare runs over time
* Every finding carries evidence, not just a verdict
* Every chart is rendered server-side as SVG — nothing fetched from a CDN, nothing executed in
  the browser beyond the page itself

## 📊 Real Data, Hand-Rendered Visuals

This is **not** an animated mockup — it is a working tool that reads real data from this host or
the file/input you give it, and renders it with:

* 🎯 Server-side SVG charts (no JS charting library, no CDN)
* 📈 Scan-to-scan history and trend views
* 🔎 Filterable findings/results tables
* 🧭 A 404 handler and empty-state pages instead of blank crashes
* 💻 A CLI that mirrors everything the web app can do

## 🔥 Key Features (SEO Optimized)

* Read-only local analysis
* SQLite-backed scan history
* SVG analytics charts
* 5-page web dashboard

## 🧩 What It Covers

* Read-only local analysis
* SQLite-backed scan history
* SVG analytics charts
* 5-page web dashboard

## 🖥️ CLI

```
(see --help for the full command list)
```

## 🛠️ Tech Stack

* 🐍 Python 3.12+ (standard library only for the core logic)
* 🌶️ Flask — web app (optional; the CLI works without it)
* 🗄️ SQLite — scan history and findings storage
* 🖼️ Hand-generated SVG — charts, no external JS/CSS dependency


## 🎨 Design Philosophy

* 🌑 Read-only by default — nothing is changed on the host or target
* 🧠 Evidence-first — every finding shows *why*, not just *what*
* 📊 Data clarity over clutter
* ⚡ One file, fully auditable
* 🎯 Analyst-focused UX, both in the terminal and the browser

## 📈 SEO Keywords

ConnTrack · Digital Forensics Tool · Cybersecurity CLI Utility · DFIR Dashboard · Security Audit Tool
· Network Forensics · Host Security Scanner · Python Security Tool · Offline Security Analysis ·
Open Source Security Utility

## ❓ Frequently Asked Questions (AEO)

**What does ConnTrack do?**
ConnTrack is a read-only Python CLI and web app that reads every TCP connection with its queues, retransmit count and timer, tracks how long each has been in its state, and says which process owns it. One Python file, a CLI and a 5-page web app, SQLite history, SVG visuals.

**Does ConnTrack send any data over the network or to third parties?**
No. ConnTrack performs local analysis only. There is no telemetry, no external API calls beyond
what its own documented function explicitly requires (if any), and no data leaves the host
unless you export a report yourself.

**Does ConnTrack modify my system?**
No. It is read-only. It inspects and reports; it does not change configuration, files, or
running services.

**Is ConnTrack a replacement for professional security software?**
No. It is a heuristic, educational and portfolio-grade tool. See the disclaimer below.

**What do I need to run ConnTrack?**
Python 3.12 or newer. Flask is required only if you want the web app; the CLI works without it.
Run `python3 conntrack.py selftest` first to verify your environment.

## ⚠️ Professional Disclaimer

🚨 **IMPORTANT — READ BEFORE RUNNING**

* ❌ This is **not** certified security software and carries **no warranty of any kind**.
* ❌ It does **not** replace a professional penetration test, a licensed forensic examiner, or
  commercial EDR/SIEM tooling.
* ❌ Findings are **heuristics, not proof**. A clean result does not mean a system is secure, and
  a flagged result does not mean it is compromised — verify everything manually.
* ✅ **Authorised use only.** Only run this against hosts, networks, files or accounts you own or
  have explicit written permission to test. Unauthorized scanning of systems you do not own or
  control may be illegal in your jurisdiction.
* ✅ **Read-only, offline by design.** No telemetry, no third-party services, no hidden network
  calls beyond what the tool's own documented purpose requires.
* ✅ The author accepts **no liability** for any loss, damage, misuse, or legal consequence
  arising from the use, misuse, or misinterpretation of this tool or its output.
* ✅ Reports produced by this tool can contain sensitive information (accounts, ports,
  configuration, personal data). Handle and share exported reports carefully.

This project is provided **"as is"**, for learning, portfolio demonstration, and authorised
security work only.

## 🚀 About Me

Hi, I'm **Karanam Shrivasta**, a Cyber Security enthusiast focused on:

* Digital Forensics
* Ethical Hacking
* Network Security
* AI in Cybersecurity

💥 Building real-world, working security tools — not mockups.

[GitHub](https://github.com/mrshrivasta) · [LinkedIn](https://www.linkedin.com/in/karanam-shrivasta/)
