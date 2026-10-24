# Phishing Website Detection

**Student:** Pawan Kumar Shoundik  
**Program:** IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares

## Overview
A beginner-friendly Python command-line tool that analyzes URL text for common phishing warning signs. It checks URL scheme, IP-address hosts, `@`, long hostnames/URLs, multiple hyphens, many subdomains, punycode labels, known URL shorteners, and sensitive-action words in the path/query.

**Safety:** The program does not open or fetch the URL. Its score is a transparent heuristic, not a machine-learning prediction or guarantee of safety.

## Requirements
- Python 3.9+
- No third-party packages (standard library only)

## Run
1. Put this Python file and `requirements.txt` in one folder.
2. Open Terminal/Command Prompt in that folder.
3. Optional: `python -m pip install -r requirements.txt` (no external packages needed).
4. Interactive: `python PawanKumarShoundik_PhishingWebsiteDetection.py`
5. Direct: `python PawanKumarShoundik_PhishingWebsiteDetection.py "http://example.invalid/login"`
6. Tests: `python PawanKumarShoundik_PhishingWebsiteDetection.py --self-test`

Use reserved example domains for demos. Do not open suspicious URLs just to test this program. If your system uses `python3`, replace `python` with `python3`.

## Dataset information
This version is rule-based and does **not** train a machine-learning model or require an external dataset. It uses hand-written rules and synthetic test URLs; no dataset-based accuracy claims are made.

Possible future research sources:
- UCI Phishing Websites: https://archive.ics.uci.edu/dataset/327/phishing+websites — engineered features and labels, not simply raw URLs; requires a separate compatible feature pipeline.
- PhishTank: https://www.phishtank.com/ — community phishing reports/data resources; check current access terms and formats.
- Tranco: https://tranco-list.eu/ — popular-domain list that may support benign-domain comparisons; document dates, sampling, and limitations.

Do not collect credentials or visit live malicious URLs. Document source, license, collection date, labeling and preprocessing if adding a dataset.

## How it works
The program parses the URL string locally, applies explainable rules, adds rule weights into a 0–100 heuristic score, and prints the reasons. It does not inspect page content, DNS, certificates, redirects, or reputation feeds.

## Limitations
A low score does not prove a URL is safe; legitimate sites can trigger warnings and phishing sites can evade simple rules. Use browser protections, multi-factor authentication, and trusted reporting channels. This is an educational prototype, not production security software.

## References
- UCI Phishing Websites: https://archive.ics.uci.edu/dataset/327/phishing+websites
- PhishTank: https://www.phishtank.com/
- Tranco: https://tranco-list.eu/
- Python `urllib.parse`: https://docs.python.org/3/library/urllib.parse.html
