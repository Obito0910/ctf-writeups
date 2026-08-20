# 🛠️ TryHackMe Writeup – Exposed Git Repository & Werkzeug Debugger Analysis

> **Room Objective:** Discover sensitive information exposed through a publicly accessible Git repository and understand how the Werkzeug Debugger PIN mechanism works.

---

# 📌 Overview

During the assessment, an exposed **Git repository** was discovered on the web server. By dumping the repository contents, it was possible to recover the application's source code and identify sensitive information left inside development files.

Afterward, the Flask/Werkzeug debugging mechanism was analyzed to understand how the debugger PIN is generated and why attackers often combine it with vulnerabilities such as **Local File Inclusion (LFI)**.

---

# 🔍 Step 1 – Discovering the Exposed Git Repository

While enumerating the target web server running on **port 8080**, the hidden Git directory was found to be publicly accessible.

```
http://TARGET:8080/.git/
```

An exposed `.git` directory is a critical security issue because it can allow attackers to reconstruct the entire application's source code.

---

# 📥 Step 2 – Dumping the Repository

To recover the repository, **git-dumper** was used inside a Python virtual environment.

```bash
python3 -m venv venv
source venv/bin/activate

git-dumper http://TARGET:8080/.git dump_repo
```

The tool successfully reconstructed the Git repository inside:

```
dump_repo/
```

---

# 🔎 Step 3 – Searching the Source Code

After dumping the repository, the next step was to search for sensitive information.

Using `grep`, every file was searched recursively.

```bash
grep -R "THM{" dump_repo
```

The search revealed the flag inside the project documentation.

```
dump_repo/README.md
```

---

# 🚩 Flag

```
THM{byt3_l0tus_n3v3r_f0rg3ts}
```

---

# 🧠 Understanding the Werkzeug Debugger

The room also introduces the **Werkzeug Debugger**, which is commonly used by Flask applications during development.

When a Flask application runs with:

```python
debug=True
```

or

```python
FLASK_DEBUG=1
```

an unhandled exception exposes an interactive debugging console.

```
/console
```

This console allows execution of arbitrary Python code, making it extremely dangerous if exposed publicly.

---

# 🔐 Why Does Werkzeug Use a PIN?

To prevent unauthorized access, Werkzeug protects the debugger with a **PIN**.

The important point is that this PIN is **not random**.

Instead, it is generated **deterministically** using multiple system attributes collected when the application starts.

---

# ⚙️ Public Bits

Werkzeug gathers several values that are relatively easy to identify.

These include:

- Operating system username
    
- Python module name
    
- Flask/Werkzeug application class
    
- Absolute path of the application
    

Example values:

```
Username:
root

Module:
flask.app

Application:
Flask

Path:
/usr/local/lib/python3.11/site-packages/flask/app.py
```

---

# 🔒 Private Bits

Werkzeug also uses machine-specific information that should not normally be accessible remotely.

These include:

- MAC address
    
- Machine ID
    
- Boot ID
    
- cgroup information
    

Typical files include:

```
/sys/class/net/eth0/address

/etc/machine-id

/proc/sys/kernel/random/boot_id

/proc/self/cgroup
```

These values make the PIN unique for each system.

---

# 💥 Why Does Metasploit Ask for MAC Address and Machine ID?

The Metasploit module:

```
exploit/multi/http/werkzeug_debug_rce
```

attempts to reproduce Werkzeug's PIN generation algorithm.

Running:

```text
show options
```

reveals parameters such as:

- MACADDRESS
    
- MACHINEID
    
- CGROUP
    
- USERNAME
    

These correspond directly to the values Werkzeug uses internally.

Without these values, the correct debugger PIN cannot be calculated.

---

# 🔍 How Attackers Obtain These Values

In real-world attacks, an exposed debugger alone is usually **not enough**.

Attackers often combine it with another vulnerability such as:

- Local File Inclusion (LFI)
    
- Directory Traversal
    
- Arbitrary File Read
    

These vulnerabilities allow reading files like:

```
/etc/machine-id
```

or

```
/sys/class/net/eth0/address
```

Once these values are obtained, the attacker can calculate the debugger PIN and gain access to the interactive Python console.

This effectively results in **Remote Code Execution (RCE)**.

---

# 🛡️ Security Recommendations

## 1. Disable Debug Mode

Never deploy Flask applications with debugging enabled.

```python
app.run(debug=False)
```

Environment variables should also enforce production mode.

```
FLASK_ENV=production

FLASK_DEBUG=0
```

---

## 2. Block Access to Git Repositories

The `.git` directory should never be publicly accessible.

### Nginx

```nginx
location ~ /\.git {
    deny all;
    return 404;
}
```

---

## 3. Remove Sensitive Files

Ensure the following are never exposed:

- `.git`
    
- `.env`
    
- Backup files
    
- Database dumps
    
- Configuration files
    

---

## 4. Sanitize Commit History

Before deployment:

- Remove passwords
    
- Remove API keys
    
- Remove tokens
    
- Remove test credentials
    
- Remove development flags
    

Remember that deleting a file is **not enough** if it still exists in Git history.

---

# 🎯 Lessons Learned

This exercise demonstrates how a seemingly small misconfiguration—such as exposing a `.git` directory—can quickly escalate into a serious security issue.

By reconstructing the repository, an attacker may uncover:

- Application source code
    
- Credentials
    
- Secrets
    
- Internal documentation
    
- Hidden endpoints
    
- Challenge flags
    

The walkthrough also highlights why the Werkzeug Debugger should never be enabled in production. Although protected by a PIN, that PIN is derived from predictable system attributes. If an attacker can obtain those values through another vulnerability, the debugger can become an entry point for full **Remote Code Execution (RCE)**.

---

# ✅ Summary

|Item|Result|
|---|---|
|Vulnerability|Publicly Accessible `.git` Repository|
|Tool Used|`git-dumper`|
|Repository Recovered|✅ Yes|
|Flag Found|`THM{byt3_l0tus_n3v3r_f0rg3ts}`|
|Flag Location|`README.md`|
|Additional Topic|Werkzeug Debugger PIN Generation|
|Potential Impact|Source Code Disclosure → PIN Recovery → Remote Code Execution|

---

_Writeup by Obito Uchiha — Team AKATSUKI_