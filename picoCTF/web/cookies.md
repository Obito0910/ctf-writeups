# 🍪 picoCTF Writeup — Cookies Challenge# Writeup: Cookies Challenge

**Challenge:** Cookies  
**Author:** madStacks  
**Description:** Who doesn't love cookies? Try to figure out the best one.  
**Points:** (Typically 40 points in picoCTF)

## Initial Analysis

The challenge presented a simple web application accessible at `http://wily-courier.picoctf.net:60745/`. Upon initial examination of the page source, a comment was discovered:

```html
<!-- Categories: success (green), info (blue), warning (yellow), danger (red) -->
```

This hint suggested the application used category-based messaging, potentially controlled via HTTP cookies.

## Enumeration Methodology

1. **Initial Site Interaction:** The main page appeared to be a simple web interface with no immediately visible functionality.

2. **Cookie Discovery:** Intercepting requests with Burp Suite revealed that the application set a cookie named `name` with an initial value (likely 0 or 1).

3. **Cookie Manipulation:** By modifying the `name` cookie value in intercepted requests, different responses were observed:
   - Values like `-1` to `1` returned generic messages: "I love chocolate chip cookies!" and "That is a cookie! Not very special though..."
   - This confirmed the application's behavior changed based on the `name` cookie value.

## Exploitation

A systematic approach was employed to test various cookie values:

1. **Manual Testing:** Initially testing values from `-1` to `10` revealed incremental changes in response messages but no flag.

2. **Extended Enumeration:** Continuing to test higher values eventually led to a breakthrough at `name=18`.

3. **Flag Discovery:** When accessing the `/check` endpoint with `name=18`, the application responded with:

```html
<p style="text-align:center; font-size:30px;"><b>Flag</b>: <code>picoCTF{3v3ry1_l0v3s_c00k135_a4dadb49}</code></p>
```

## Verification

The flag was verified using curl:

```bash
curl -X GET --cookie "name=18" http://wily-courier.picoctf.net:60745/check
```

The response confirmed the flag was successfully retrieved.

## Solution Summary

The vulnerability was an **insecure direct object reference** via cookie manipulation. 
The application used the `name` cookie value to determine which message to display without proper access controls. 
By testing sequential integer values for the cookie, the "best cookie" (value 18) was discovered, which granted access to the flag.

**Flag:** `picoCTF{3v3ry1_l0v3s_c00k135_a4dadb49}`

## Tools Used
- Web Browser (for initial reconnaissance)
- Burp Suite (for request interception and manipulation)
- curl (for command-line verification)

This challenge demonstrated the importance of proper input validation and access control mechanisms in web applications, 
particularly when user-controlled parameters like cookies determine application behavior.


**Category:** Web Exploitation  
**Difficulty:** Easy  

---

## 🧩 Description
The challenge required identifying the “best cookie” by analyzing how the web application handled HTTP cookies.

---

## 🔎 Reconnaissance
Viewing page source revealed hints suggesting category-based responses.  
Traffic inspection showed a cookie named:

name=<value>

The server response changed depending on this value.

---

## 🕵️ Enumeration
Using Burp Suite, the cookie value was modified manually.

Different integer values produced different responses, indicating the server trusted user-controlled cookie input.

---

## ⚔️ Exploitation
Sequential testing revealed that:

name=18

returned privileged content when accessing `/check`.

---

## 🚩 Flag

picoCTF{3v3ry1_l0v3s_c00k135_a4dadb49}

---

## 🧠 Vulnerability
**Insecure Direct Object Reference (IDOR)** via cookie manipulation.

The application failed to validate authorization server-side.

---

## 🛠 Tools
- Browser
- Burp Suite
- curl

---

## 📚 Lessons Learned
- Never trust client-side data.
- Predictable identifiers enable enumeration attacks.

## 🧠 What I Learned
- How cookies control server behavior
- Manual request manipulation
- Enumeration methodology
