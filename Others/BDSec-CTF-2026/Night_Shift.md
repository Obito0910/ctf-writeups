# Night Shift - BDSEC CTF Writeup

- **Challenge:** Night Shift
- **Category:** Reverse Engineering
- **Author:** NomanProdhan
- **Points:** 100
- **Flag Format:** `BDSEC{s0mething_h3re}`

---

# Challenge Description

> The building is closed, but the work is not finished. Complete the remaining assignments before morning.

---

# Initial Analysis

The first step was identifying the binary type and checking its security protections.

## File Information

```bash
file night_shift.bdsec
```

Output:

```
ELF 64-bit LSB pie executable
x86-64
Dynamically linked
Stripped
```

The binary is:

- 64-bit ELF
- PIE enabled
- Stripped (no function names)

---

## Security Protections

```bash
checksec --file=night_shift.bdsec
```

Output:

```
RELRO           Partial
Canary          Found
NX              Enabled
PIE             Enabled
Symbols         No
```

The binary contains common exploit mitigations, confirming that this is a reverse engineering challenge rather than a binary exploitation challenge.

---

# Extracting Strings

To understand the program's behavior, printable strings were extracted.

```bash
strings -n 6 night_shift.bdsec
```

Interesting strings:

```
NIGHT SHIFT

The building is closed.

Eight assignments remain.

shift code>

The shift report was rejected.

The morning report has been approved.
```

These strings immediately reveal that:

- the program expects user input
- there is a success path
- there is a failure path

---

# Opening the Binary in Ghidra

The binary was imported into Ghidra and analyzed using the default analysis settings.

Searching for

```
The morning report has been approved.
```

led directly to the main verification routine.

The decompiled code revealed the following important information.

---

# Input Validation

The program:

- reads a line using `fgets()`
- tokenizes the input using `strtok_r()`
- converts each token using `strtoul()`

Each input value must satisfy:

```
0 <= value <= 4
```

The program also requires exactly **8 integers**.

Pseudo-code:

```c
for(i=0;i<8;i++)
{
    read_number();

    if(number > 4)
        reject();
}
```

Therefore the valid input space becomes:

```
5^8
```

which equals

```
390625
```

possible combinations.

---

# Thread Analysis

The decompiler also showed that the program creates worker threads.

```
pthread_create(...)
```

Each thread executes

```
FUN_001016d0()
```

which dispatches execution using a jump table depending on the current input.

Although the internal verification logic is intentionally obfuscated, the crucial observation is that the input domain is extremely small.

---

# Choosing an Attack Strategy

At this point there were two possible approaches.

## Method 1

Reverse every verification function and recover the correct input mathematically.

Pros:

- educational
- complete reverse engineering

Cons:

- time consuming

---

## Method 2

Brute force every possible input.

Since

```
390625
```

is a very small search space, brute forcing is significantly faster.

The binary itself tells us whether an input is correct by printing

```
The morning report has been approved.
```

Therefore brute forcing becomes the optimal solution.

---

# Brute Force Script

```python
from itertools import product
import subprocess

binary = "./night_shift.bdsec"

for p in product(range(5), repeat=8):

    inp = " ".join(map(str, p)) + "\n"

    try:
        r = subprocess.run(
            [binary],
            input=inp,
            text=True,
            capture_output=True,
            timeout=0.2
        )
    except Exception:
        continue

    if "approved" in r.stdout.lower():
        print("[+] FOUND:", p)
        print(r.stdout)
        break
```

---

# Result

The script successfully found the correct input.

```
(2, 0, 4, 1, 3, 0, 2, 4)
```

Running the binary with that input produced

```
========================================
              NIGHT SHIFT
========================================

The building is closed.
Eight assignments remain.

shift code>

The morning report has been approved.

BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```

---

# Correct Input

```
2 0 4 1 3 0 2 4
```

---

# Flag

```
BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```

---

# Lessons Learned

This challenge demonstrates an important reverse engineering principle.

Before spending hours reversing complex logic, always estimate the search space.

Here,

```
5 choices
×

8 positions

=

390625 combinations
```

which is trivial for modern hardware.

Although the binary used:

- threads
- jump tables
- stripped symbols
- hash-like transformations

none of those protections mattered because the input space itself was tiny.

In many CTF reverse engineering challenges, identifying constraints early can save significant time.

---

# Tools Used

- Kali Linux
- file
- checksec
- strings
- Ghidra
- Python 3
- itertools
- subprocess

---

# Commands Used

```bash
file night_shift.bdsec

checksec --file=night_shift.bdsec

strings -n 6 night_shift.bdsec

python3 solve.py
```

---

# Final Flag

```
BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```

---

## Author's Notes

The intended reverse engineering path involves analyzing the worker-thread verification functions and the jump table used by `FUN_001016d0`.

However, because the program only accepts eight integers in the range `0–4`, the total search space is only **390,625** combinations. A simple brute-force approach is therefore the fastest and most practical solution.

```
Challenge Solved ✅
```
---

_Obito Uchiha — Team AKATSUKI_
