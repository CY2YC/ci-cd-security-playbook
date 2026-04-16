# SOURCES.md — CI/CD Security Playbook Verification References

| # | Claim | Verification Source | Date Verified |
|---|-------|---------------------|---------------|
| 1 | GitLab trigger token regex: `glptt-[a-f0-9]{40}` | GitGuardian secrets detection rules; GitLab MR !195007 | Apr 2026 |
| 2 | GitLab 18.1 setting: "Allow MR pipelines to access protected variables" | GitLab Docs: "Merge request pipelines access to protected variables and runners" | Apr 2026 |
| 3 | GitLab variable inheritance in fork MRs (2026 behavior) | GitLab epic !196304, !198754; self-hosted testing | Apr 2026 |
| 4 | `CI_MERGE_REQUEST_SOURCE_IS_FORK` predefined variable | GitLab Docs: "Predefined CI/CD variables reference" | Apr 2026 |
| 5 | GitHub Actions `GITHUB_TOKEN` fork PR permissions | GitHub Docs: "Permissions for the GITHUB_TOKEN" | Apr 2026 |
| 6 | Jenkins CVE-2024-52550 details | Jenkins Security Advisory 2024-11-13; NVD CVE-2024-52550 | Apr 2026 |
| 7 | Jenkins script approval SHA-1 collision fix | Jenkins Security Advisory 2025-01-21; Script Security 1190 | Apr 2026 |
| 8 | CircleCI context inheritance | CircleCI Docs: "Using Contexts" | Apr 2026 |
| 9 | Webhook constant-time comparison requirement | Jenkins SECURITY-2871; GitLab webhook signature docs | Apr 2026 |
| 10 | OAuth token not auto-injected in GitLab pipelines | GitLab Docs: "CI/CD variables" | Apr 2026 |

## Additional References

- **GitLab CI/CD Internals:** `lib/gitlab/ci/trigger.rb`
- **Jenkins Script Security Plugin:** `org.jenkinsci.plugins.scriptsecurity.sandbox.groovy`
- **NIST NVD:** CVSS score validation

---

*All sources accessible as of April 2026.*
