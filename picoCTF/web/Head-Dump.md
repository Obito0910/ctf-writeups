# PicoCTF Head-Dump Challenge Writeup

## Challenge Information
**Challenge**: Head-Dump  
**Category**: Web Exploitation / Forensics  
**Difficulty**: Easy-Medium  
**Description**: *Welcome to the challenge! In this challenge, you will explore a web application and find an endpoint that exposes a file containing a hidden flag.*

## Executive Summary
Discovered and exploited an exposed heap dump endpoint in a web application's API documentation to extract a hidden flag from memory artifacts.

## Technical Analysis

### Phase 1: Initial Reconnaissance
1. **Target**: `http://verbal-sleep.picoctf.net:64738/`
2. **Initial Assessment**: Basic web page with minimal content
3. **Key Discovery**: Hyperlink labeled "Document" suggesting API documentation

### Phase 2: Endpoint Discovery
1. **Documentation Access**: Clicked "Document" link
2. **Endpoint Location**: Redirected to `http://verbal-sleep.picoctf.net:64738/api-docs/`
3. **API Analysis**: Swagger/OpenAPI documentation interface revealed
4. **Critical Endpoint**: `/headdump` endpoint identified in documentation

### Phase 3: Exploitation

#### Step 1: Endpoint Interaction
**Method**: 
- Navigated to `/headdump` endpoint via API documentation interface
- Used "Try it out" feature followed by "Execute" button
- **Result**: Automatic download of `heapdump-1770576332435.heapsnapshot` file

#### Step 2: File Analysis
**File Type Identification**: `.heapsnapshot` extension indicates **V8 heap snapshot**
- **Purpose**: Memory dump for debugging Node.js applications
- **Content**: Contains memory artifacts, potentially including sensitive data

#### Step 3: Data Extraction
**Initial Analysis**: 
```bash
strings heapdump-1770576332435.heapsnapshot
```
**Observation**: Raw output too extensive, containing binary data and memory artifacts

**Targeted Extraction**:
```bash
strings heapdump-1770576332435.heapsnapshot | grep picoCTF{.*}
```
**Result**: Successfully extracted the flag pattern from memory dump

## Technical Details

### Heap Snapshot Files
- **Format**: Binary format containing V8 heap memory representation
- **Common Use**: Debugging memory leaks in Node.js applications
- **Security Risk**: Can contain sensitive data from application memory
- **Tools**: Chrome DevTools, `node-heapdump` module

### Why This Worked
1. **Information Disclosure**: API documentation exposed debug endpoints
2. **Improper Access Control**: Production access to heap dump functionality
3. **Memory Artifacts**: Flag stored in application memory at dump time
4. **String Persistence**: Flag remained in memory as cleartext string

## Security Implications

### Vulnerabilities Identified
1. **Debug Endpoints in Production**: `/headdump` endpoint accessible in production environment
2. **Insufficient Access Control**: No authentication/authorization for sensitive endpoints
3. **Information Disclosure**: Heap dumps contain application memory state
4. **Sensitive Data in Memory**: Flag stored as cleartext in application memory

### Attack Vectors
1. **Information Gathering**: Exploiting exposed API documentation
2. **Memory Analysis**: Extracting sensitive data from memory dumps
3. **Data Reconstruction**: Recovering application state from heap snapshots

## Mitigation Strategies

### For Developers:
```javascript
// SECURE IMPLEMENTATION

// 1. Environment-based endpoint exposure
if (process.env.NODE_ENV === 'production') {
  // Disable debug endpoints
  app.disable('heap-dump');
} else {
  // Development-only endpoints
  app.get('/debug/heapdump', authenticateAdmin, (req, res) => {
    // Secure, authenticated access
  });
}

// 2. Secure sensitive data in memory
const sensitiveFlag = Buffer.from(encryptedFlag, 'base64');
// Instead of: const flag = "picoCTF{...}";

// 3. Input sanitization for API documentation
app.use('/api-docs', require('swagger-ui-express'), {
  swaggerOptions: {
    validatorUrl: null
  }
});
```

### Best Practices:
1. **Environment Segregation**: Separate development and production configurations
2. **Access Control**: Implement authentication for debug endpoints
3. **Data Protection**: Encrypt sensitive data even in memory
4. **Monitoring**: Log access to sensitive endpoints
5. **Regular Audits**: Review exposed endpoints and documentation

## Flag
**Extracted Flag**: `picoCTF{Pat!3nt_15_Th3_K3y_a485f162}`

**Flag Analysis**: 
- **Pattern**: Standard picoCTF format
- **Message**: "Pat!3nt_15_Th3_K3y" suggesting patience in enumeration is key
- **Uniqueness**: Unique identifier `a485f162`

## Tools and Commands Used
1. **Web Browser**: Initial reconnaissance and endpoint discovery
2. **Terminal/Command Line**: File analysis
3. **strings utility**: Extracting readable strings from binary files
4. **grep**: Pattern matching for flag extraction

## Timeline
1. **00:00-02:00**: Initial reconnaissance and documentation discovery
2. **02:00-05:00**: Endpoint analysis and heap dump retrieval
3. **05:00-08:00**: File analysis and flag extraction
4. **Total Time**: ~8 minutes

## Key Takeaways
1. **API Documentation**: Often reveals hidden endpoints and functionality
2. **Debug Endpoints**: Should never be exposed in production environments
3. **Memory Security**: Sensitive data should not persist as cleartext in memory
4. **Binary Analysis**: Basic string extraction can reveal significant information
5. **Persistence Pays**: Systematic enumeration leads to discovery

## Conclusion
This challenge highlighted the importance of proper environment configuration and access control. 
The exposure of debug endpoints in production, combined with sensitive data in application memory, created a significant information disclosure vulnerability. 
The solution demonstrates how basic forensic techniques can extract valuable information from seemingly opaque data formats.

**Educational Value**: Emphasizes the need for secure development practices, particularly regarding debug functionality and memory management in web applications.
