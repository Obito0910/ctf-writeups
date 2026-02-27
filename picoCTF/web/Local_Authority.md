# PicoCTF: Local Authority Writeup

## Challenge Information
**Challenge**: Local Authority  
**Category**: Web Exploitation  
**Difficulty**: Easy  
**Description**: *Can you get the flag? Go to this website and see what you can discover.*

## Executive Summary
Successfully exploited a client-side authentication vulnerability through two distinct methods: 
(1) Direct credential discovery in JavaScript files, and 
(2) Authentication bypass via DOM manipulation. Both methods demonstrate critical flaws in client-side security implementations.

## Methodology 1: Direct Credential Discovery

### Step 1: Initial Reconnaissance
- **Target**: Login page at provided URL
- **Initial Testing**: Attempted common credentials (`admin:admin`)
- **Result**: "Login Failed" error message

### Step 2: Source Code Analysis
- **Inspection**: Right-click → View Page Source
- **Discovery**: Reference to external JavaScript file: `secure.js`
- **Location**: `http://[target]/secure.js`

### Step 3: Credential Extraction
**File Content Analysis**:
```javascript
function checkPassword(username, password)
{
  if( username === 'admin' && password === 'strongPassword098765' )
  {
    return true;
  }
  else
  {
    return false;
  }
}
```

**Identified Credentials**:
- **Username**: `admin`
- **Password**: `strongPassword098765`

### Step 4: Authentication Bypass
- **Action**: Submitted discovered credentials
- **Result**: Successful login → Flag revealed

## Methodology 2: Authentication Bypass via DOM Manipulation

### Step 1: Alternative Code Path Discovery
Upon failed login attempt with `admin:admin`, additional JavaScript was revealed:

**Vulnerable Code Analysis**:
```javascript
// Filter function - allows alphanumeric characters only
function filter(string) {
  // ... alphanumeric validation logic ...
}

window.username = "admin";
window.password = "admin";

// After validation, authentication occurs
loggedIn = checkPassword(window.username, window.password);

if(loggedIn) {
  document.getElementById('adminFormHash').value = "2196812e91c29df34f5e217cfd639881";
  document.getElementById('hiddenAdminForm').submit();
}
```

### Step 2: Vulnerability Identification
**Critical Flaws**:
1. **Hardcoded Hash**: `2196812e91c29df34f5e217cfd639881`
2. **DOM Accessibility**: Form elements accessible via JavaScript
3. **Client-side Logic**: Authentication decisions made client-side

### Step 3: Exploitation via Console
**Browser Console Attack**:
```javascript
// Method A: Direct hash submission
document.getElementById('adminFormHash').value = "2196812e91c29df34f5e217cfd639881";
document.getElementById('hiddenAdminForm').submit();

// Method B: Function override (alternative)
function checkPassword() { return true; }
// Then trigger the existing login flow
```

### Step 4: Successful Bypass
- **Result**: Form submission with valid hash
- **Outcome**: Redirect to authenticated area → Flag retrieval

## Technical Analysis

### Vulnerability 1: Insecure Credential Storage
**Location**: `secure.js` file  
**Issue**: Plaintext credentials in client-side code  
**Impact**: Any user can view source to obtain credentials  
**CVSS Score**: 7.5 (High)

### Vulnerability 2: Client-side Authentication
**Location**: Main page JavaScript  
**Issue**: Security decisions made in browser  
**Impact**: Users can bypass/override validation logic  
**CVSS Score**: 8.1 (High)

### Vulnerability 3: Hardcoded Secrets
**Location**: MD5 hash in JavaScript  
**Issue**: Static authentication token  
**Impact**: Token replay attacks possible  
**CVSS Score**: 6.5 (Medium)

## Comparative Analysis

| Aspect | Method 1 | Method 2 |
|--------|----------|----------|
| **Complexity** | Low (View source) | Medium (Console manipulation) |
| **Technical Skill** | Beginner | Intermediate |
| **Time Required** | < 2 minutes | < 5 minutes |
| **Reliability** | 100% (Direct credentials) | 100% (Hash replay) |
| **Learning Value** | Basic recon | Advanced exploitation |

## Security Implications

### For Developers:
1. **Never store credentials client-side**
2. **Implement server-side authentication only**
3. **Use secure session management**
4. **Employ proper input validation**
5. **Avoid hardcoded secrets in source**

### Code Fix Example:
```javascript
// ❌ VULNERABLE (Client-side)
function checkPassword(username, password) {
  return username === 'admin' && password === 'secret';
}

// ✅ SECURE (Server-side API call)
async function authenticate(username, password) {
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password})
  });
  return response.ok;
}
```

## Flag Analysis
**Flag**: `picoCTF{j5_15_7r4n5p4r3n7_05df90c8}`  
**Decoded Message**: "js_is_transparent_05df90c8"  
**Meaning**: JavaScript source code is transparent/visible to users

## Tools Used
1. **Web Browser**: Navigation and source viewing
2. **Developer Tools**: Console for JavaScript execution
3. **No specialized tools required**

## Timeline
- **Method 1**: 0-2 minutes (Direct credential discovery)
- **Method 2**: 2-5 minutes (Console exploitation)
- **Total**: < 5 minutes for complete solution

## Key Takeaways
1. **Source Code Examination**: Always check HTML/JS files for secrets
2. **Client-side Insecurity**: Browser-executed code is user-modifiable
3. **Defense in Depth**: Single security layer is insufficient
4. **Transparency**: Client-side code is always visible to end-users

## Educational Value
This challenge teaches:
- Importance of server-side validation
- Dangers of client-side security logic
- Basic web reconnaissance techniques
- JavaScript debugging and manipulation skills

## Recommendations for Improvement
1. **Move authentication to server-side**
2. **Implement HTTPS for all communications**
3. **Use secure cookies with HttpOnly flag**
4. **Add CSRF protection**
5. **Implement rate limiting on login attempts**
6. **Use secure password hashing (bcrypt, Argon2)**

## Conclusion
The "Local Authority" challenge effectively demonstrates why client-side authentication is fundamentally insecure. 
Both exploitation methods highlight how transparent client-side code enables attackers to bypass security controls. 
The flag's message "js_is_transparent" perfectly encapsulates the core lesson: anything running in the user's browser can be inspected, modified, and exploited.

This vulnerability pattern is common in real-world applications, making this challenge both educational and practically relevant for understanding web application security principles.
