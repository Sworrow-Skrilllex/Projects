# Projects
# Automated Security Assessment Pipeline (ASAP)

An autonomous security automation framework designed to address operational inefficiencies in the initial reconnaissance phase of a security assessment by orchestrating industry-standard tools into a unified pipeline.

## Features
- **Central Orchestration:** Utilizes Python's `subprocess` module to manage execution flow and data handoffs[cite: 6].
- **Intelligent Port Parsing:** Deploys a custom regular expression engine to automatically parse Nmap output and identify open web services.
- **Bifurcated Workflow:** Automatically launches targeted scans (`GoBuster` for file/directory enumeration and `Nikto` for web vulnerability scanning) only when web ports are discovered[cite: 7].
- **Consolidated Reporting:** Automatically aggregates all scan data, assigns heuristic severity levels, and compiles a structured report[cite: 7].

## Included Documentation & Code
- `recon.py`: Core Python automation script.
- `ASAP_Synopsis.pdf`: Formal academic project synopsis and technical documentation.
- `ASAP_Presentation.pptx`: Comprehensive project slide deck.

## Author
Mohammed Gause Ayaz Shaikh
