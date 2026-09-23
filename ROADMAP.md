# Roadmap / ideas

Comment on (or open) an issue first so we don't duplicate work.

## Good first issues
- [ ] Split the 3,400-line `cyberscan.ps1` into a module (`.psm1`) with one file per check category
- [x] Add screenshots of the dashboard and an example HTML report to the README
- [ ] Add a `-Version` switch and a single version constant
- [ ] Publish to the PowerShell Gallery

## Checks
- [ ] More CIS Benchmark controls (Windows 11, Server 2022)
- [ ] Defender / firewall / BitLocker / TPM summary card
- [ ] Browser extension and startup-persistence review
- [ ] Export results as JSON/CSV for SIEM or spreadsheets
- [ ] Headless mode (`-NoGui -Report out.html`) for scheduled audits and RMM tools

## Quality
- [ ] Pester tests for the scoring and ATT&CK-tagging helpers
- [ ] PSScriptAnalyzer clean-up
- [ ] Sign the script and ship releases from GitHub Actions
