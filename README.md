[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](LICENSE)
[![Project Status: Active](https://img.shields.io/badge/Status-Active-brightgreen)](https://github.com/CY2YC/ci-cd-security-playbook)
[![Last Commit](https://img.shields.io/github/last-commit/CY2YC/ci-cd-security-playbook)
]


# CI/CD Security Playbook

## Overview

A comprehensive defensive playbook covering **8 CI/CD flaw categories** across:
- **GitLab CI/CD**
- **GitHub Actions**
- **CircleCI**
- **Jenkins**

Designed for security engineers, bug bounty hunters, and DevSecOps teams conducting authorized testing.

## What's Inside

| File | Description |
|------|-------------|
| [`PLAYBOOK.md`](PLAYBOOK.md) | Main playbook: threat models, test payloads, detection signals, and mitigations |
| [`SOURCES.md`](SOURCES.md) | Verified references for all technical claims |
| [`examples/`](examples/) | Standalone YAML/Groovy/Python payload examples |

## Flaw Categories Covered

1. Fork MR Variable Leakage
2. Runner-Tag Misbinding
3. Group Variable Inheritance
4. Webhook Signature Flaws
5. Artifact Poisoning
6. Trigger Token Leakage
7. OAuth/SSO Misbinding
8. Jenkins Sandbox Bypass & Plugin Vulnerabilities

## Detection Engineering

Includes ready-to-use detection rules for:
- Splunk SPL queries
- Elastic/Kibana JSON rules
- Sigma YAML rules
- SQL queries for log analysis

## ⚠️ Disclaimer

**For authorized security testing and educational purposes only.**

Do not use these techniques on any system without explicit written permission. Unauthorized testing is illegal and violates platform terms of service.

## License

This work is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).

- **Attribution Required** — Cite this repository
- **Non-Commercial** — No commercial use without permission
- **ShareAlike** — Derivatives must use same license

## Contributing

Found an error or have an addition? Open an issue or pull request with:
- Clear description of the change
- Supporting evidence (docs, CVE references)
- Verified test case (if applicable)

---
*Maintained by CY2YC*
