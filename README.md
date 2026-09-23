# CyberScan

A free, all-in-one **Windows security audit and hardening dashboard** written in PowerShell. Point it at a PC, get a security score, see what is wrong, and fix it - with an undo log for every change.

> "TITAN ULTIMATE" edition v10.0 - 110+ checks in a single script. Built by a working IT technician for quick, repeatable health-and-security checks on client and home-lab machines.

## What it does

- **110+ operations** in one GUI (Windows Forms) with a live dashboard (CPU / RAM / network gauges)
- **Security scoring** - a single score for the machine plus per-check results
- **CVE scanner** and **CIS baseline** checks
- **Threat-intel style checks** - established connections mapped to processes, suspicious/known-backdoor ports, programs running from user/temp folders
- **MITRE ATT&CK mapping** - findings are tagged with technique IDs and tactics
- **Full audit suite + HTML report**
- **Fix prompts with undo** - changes are logged so you can roll them back
- **Scan history** and system snapshot

Also included: [`tools/nmap_studio.py`](tools/nmap_studio.py), a small dark-mode GUI wrapper around [nmap](https://nmap.org/).

## Requirements

- Windows 10 / 11, Windows PowerShell 5.1 or PowerShell 7
- Run as **Administrator** for the full set of checks
- Optional: [nmap](https://nmap.org/download.html) + Npcap for Nmap Studio (`pip install customtkinter`)

## Quick start

1. Download or clone this repo.
2. Right-click `CyberScan_Setup.bat` -> **Run**. It self-elevates, runs `_setup_helper.ps1` (execution policy, PowerShell 7 if missing) and launches CyberScan.

or from an elevated PowerShell:

```powershell
git clone https://github.com/ronaldgoodchild/cyberscan.git
cd cyberscan
powershell -ExecutionPolicy Bypass -File .\cyberscan.ps1
```

Data (scan history, undo log) is stored in `%USERPROFILE%\.cyberscan`.

## Safety

- CyberScan **audits the machine it runs on**. Only use it on systems you own or are authorised to assess.
- "Fix" actions change system settings. Read each prompt; every change is written to the undo log. Use at your own risk.
- `_setup_helper.ps1` changes the PowerShell execution policy and may install PowerShell 7 - read it before running.

## Contributing

Ideas and pull requests welcome - see [CONTRIBUTING.md](CONTRIBUTING.md) and [ROADMAP.md](ROADMAP.md).

## License

[MIT](LICENSE) (c) 2026 Ronald Goodchild / REGTeches
