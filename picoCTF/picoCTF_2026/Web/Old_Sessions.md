
---

## **CTF Writeup: Old Sessions (picoCTF)**

### **Challenge Overview**

- **Category:** Web Exploitation
    
- **Points:** 100
    
- **Target:** `http://dolphin-cove.picoctf.net:64840/`
    
- **Vulnerability:** Broken Access Control / Insecure Session Management
    

### **1. Initial Reconnaissance**

The challenge description highlights that the site's developer "hates constantly logging in" and configured sessions to never expire. Upon visiting the link, I registered a new account with the username **"obito"**.

After logging in, I landed on the homepage. While reviewing the user comments section, a specific entry from a user named `mary_jones_8992` caught my attention:

> _"Hey I found a strange page at /sessions"_

### **2. Vulnerability Discovery**

I navigated to the hidden `/sessions` endpoint. This page exposed a list of all active sessions currently stored in the application's memory:

1. `session:GzSEJV6t6OYxZOXZgaDUfsELDWC_VoidXCBO2MXmuPM, {'_permanent': True, 'key': 'admin'}`
    
2. `session:6_EpShuLA_mUmaLofGN2kS0sYau-_dqMW83chlGgpEE, {'_permanent': True, 'key': 'obito'}`
    

The data revealed that the **admin** session was active and set to `_permanent: True`, meaning it would not time out.

### **3. Exploitation (Session Hijacking)**

To access the admin account without a password, I performed a **Session Hijacking** attack:

1. Opened the browser **Developer Tools** (F12).
    
2. Navigated to the **Application** (Chrome/Edge) or **Storage** (Firefox) tab.
    
3. Located the **Cookies** section for the challenge URL.
    
4. Replaced my current session cookie value with the admin's token:
    
    - **Original:** `6_EpShuLA_mUmaLofGN2kS0sYau-_dqMW83chlGgpEE`
        
    - **New (Admin):** `GzSEJV6t6OYxZOXZgaDUfsELDWC_VoidXCBO2MXmuPM`
        
5. **Refreshed** the page.
    

### **4. Result**

Upon refreshing, the server recognized the hijacked cookie as a valid admin session. The homepage updated to welcome the "Admin," revealing the flag.

**Flag:** `picoCTF{****_********_***********_****}`

---

_Writeup by: obito | picoCTF 2026_
