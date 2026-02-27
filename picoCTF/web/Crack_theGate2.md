# **Crack the Gate 2 — Bypassing Rate Limiting via X-Forwarded-For Header**

## **Challenge Overview**
The challenge presents a login system protected by a **basic rate-limiting mechanism** that locks out IP addresses after repeated failed login attempts. The goal is to bypass this restriction and brute-force the password for the email `ctf-player@picoctf.org`.

---

## **Reconnaissance**
1. **Initial Testing**  
   - Attempted to log in with the given email and a random password.  
   - After **2 failed attempts**, the system blocked the IP address for **20 minutes**, confirming rate-limiting behavior.

2. **Hint Analysis**  
   - The challenge description hinted that the system **"might still trust user-controlled headers"**.  
   - In web applications, common headers like `X-Forwarded-For`, `X-Real-IP`, and `X-Originating-IP` are often used to identify client IPs behind proxies.

3. **Password List**  
   - A password list was provided, confirming the need for a **brute-force attack**.

---

## **Attack Strategy**
The rate-limiting mechanism likely tracks requests **per IP address**. If the system uses the `X-Forwarded-For` header to determine the client IP, we can spoof this header to bypass the lockout.

**Plan:**
- Intercept login requests with Burp Suite.
- Add/modify the `X-Forwarded-For` header with a new IP for each attempt.
- Automate password tries using a wordlist.

---

## **Exploitation Steps**

### **1. Intercept Request**
- Captured a login POST request to `/login` with Burp Suite.
- Observed the request format:
  ```http
  POST /login HTTP/1.1
  Host: ...
  Content-Type: application/x-www-form-urlencoded

  email=ctf-player@picoctf.org&password=test123
  ```

### **2. Bypass Rate Limiting**
- Added the header:
  ```
  X-Forwarded-For: 203.0.113.195
  ```
- Each time the rate limit triggered, the header was changed to a **new IP** (e.g., `203.0.113.196`, `203.0.113.197`, etc.).
- This tricked the system into treating each request as coming from a **different client**.

### **3. Brute-Force Automation**
- Used **Burp Intruder** to automate the attack:
  - Set the **password** field as the first payload position (using the provided wordlist).
  - Set the **X-Forwarded-For** header as the second payload position (using a list of arbitrary IPs).
- Configured **pitchfork attack** mode to iterate through both lists simultaneously.

### **4. Success Response**
- After several attempts, one request returned a **different response length**.
- The response contained the **flag** in plaintext:
  ```html
  picoCTF{xff_byp4ss_brut3_f6cca7d4}
  ```

### **5. Manual Login**
- Used the discovered password in the web interface.
- A popup displayed the flag, confirming success.

---

## **Vulnerability Explanation**
The system **incorrectly trusted the `X-Forwarded-For` header** for client identification. Since this header can be controlled by the user, attackers can **spoof their IP address** to evade rate limits.

**Mitigation:**
- Do not rely solely on user-supplied headers for IP-based rate limiting.
- Use a combination of connection IP, session tokens, and other immutable identifiers.
- Implement CAPTCHA or exponential backoff after repeated failures.

---

## **Flag**
**`picoCTF{xff_byp4ss_brut3_f6cca7d4}`**

---

## **Tools Used**
- **Burp Suite** (Proxy, Repeater, Intruder)
- **Provided password wordlist**

## **Key Learning**
- **User-controlled headers** should never be trusted for security mechanisms like rate limiting.
- **Defense-in-depth** is critical—always validate and sanitize all inputs, including HTTP headers.
