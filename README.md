# CensorTrace Suite
### Internet Censorship Research & Diagnostic Toolkit

## Overview

CensorTrace Suite is a combined research and engineering project focused on analyzing, measuring, and documenting Internet censorship mechanisms — with a special focus on multi-layer filtering architectures such as those deployed in Iran.

This repository contains:

- Two technical research papers
- A Python-based censorship diagnostic tool
- Measurement methodology and sample results

Designed for:

- Network engineers
- ISP operators
- Censorship-measurement researchers
- Cybersecurity analysts
- Students and academics studying network interference

---

## Repository Contents

### /papers/
Technical whitepapers:
- The Silent Walls of the Web
- Iran’s Multi-Layer Internet Censorship Architecture

### /tools/censortrace/
Python-based censorship diagnostic CLI tool:
- DNS testing (UDP/TCP/DoH/DoT)
- Dig-style DNS parsing
- HTTP/HTTPS censorship detection
- TLS SNI probing
- TCP reset detection
- Throttling measurement
- Traceroute and ping integration
- Packet export

Includes:
- censortrace_cli.py
- requirements.txt
- Tool-specific README

### /data/sample-results/
Example outputs from real-world tests.

### /docs/methodology.md
Explains:
- Measurement design
- Test logic
- Detection heuristics
- Interpretation of results

---

## Installation

cd tools/censortrace
pip install -r requirements.txt

---

## Usage

python censortrace_cli.py --domain youtube.com

Optional flags:
--dns-timeout
--http-timeout
--tls-timeout
--host-header
--sni
--http-ip
--json
--export-packets

---

## License

This project is licensed under the MIT License.

---

## Citation

CensorTrace Suite: Internet Censorship Research & Diagnostics  
https://github.com/9t3o5st/censortrace-suite

---

## Contributions

Pull requests are welcome for:
- New measurement modules
- Additional research papers
- Localization and documentation
- Dataset contributions

---

## Contact

For questions or collaboration, open an issue on GitHub.
