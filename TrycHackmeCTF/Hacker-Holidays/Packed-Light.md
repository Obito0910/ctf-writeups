# Writeup: # Packed Light - Traffic Analysis & Exfiltration

## Overview

During the analysis of the network traffic capture (`traffic.pcapng`), we investigated a malicious HTTP data exfiltration mechanism. The analysis focuses on a custom Python script (`updates.py`) acting as a keylogger, which communicated with a Command and Control (C2) server located at `[http://byte-lotus-hotel.thm:8080/](http://byte-lotus-hotel.thm:8080/)`.

## Analysis & Investigation

### 1. Identifying the Covert Channel

By analyzing the HTTP traffic within Wireshark or via command-line tools like `tshark`, we observed multiple sequential `GET` requests sent to the C2 server.

- The malware exfiltrated captured keystrokes chunk by chunk across multiple requests rather than sending them all at once.
    
- To bypass network detection and blend in with standard web traffic, the data was hidden inside an HTTP `Cookie` header named `hotel_sess_state`.
    

### 2. Extracting the Cookies

Using `tshark`, we filtered out the traffic containing the specific tracking cookies:

Bash

```
tshark -r traffic.pcapng -Y 'http.cookie contains "hotel_sess_state"' -T fields -e http.cookie
```

This extracted the sequence of short Base64-encoded chunks corresponding to each captured character:

Plaintext

```
HA== AA== BQ== Mw== Hg== ew== Og== fA== Fw== eQ== Ow== Fw== Pw== fA== PA== Kw== IA== eQ== Jg== Lw== Fw== eA== Pg== LQ== Gg== Fw== MQ== eA== PQ== NQ==
```

### 3. Decrypting the Payload

- **The Cipher Mechanism:** The script encrypted each character using a single-byte XOR operation.
    
- **Finding the Key:** By evaluating the first packet's known structure against the expected initial format of the flag (`THM{...}`), we determined that the single-byte XOR key was the character **`"H"`** (Hex: `0x48`).
    
- **Reassembly:** Decoding the Base64 values and applying the XOR key across each individual sequence successfully reconstructed the complete hidden flag:
    

Plaintext

```
THM{V3r4_1s_w4tch1ng_0veR_y0u}
```

---

_Writeup by Obito Uchiha — Team AKATSUKI_