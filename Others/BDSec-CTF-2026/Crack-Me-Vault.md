# Crack Me Vault — BDSEC CTF 2026

**Category:** Reverse Engineering **Points:** 150 **Author:** NomanProdhan **Flag:** `BDSEC{c0nTr0L_fl0w_1s_4_l13_bUt_bYt3c0d3_d03s_n0t}`

---

## 1. Recon

```
$ file crack_me_vault.bdsec
ELF 64-bit LSB pie executable, x86-64, stripped
RELRO: Partial, Canary: yes, NX: enabled, PIE: enabled
```

Running it shows a straightforward flag-checker prompt behind some ASCII art:

```
====================================
       BDSec CTF 2026
    THE BYTECODE VAULT
====================================

Enter the flag:
[-] Access denied.
```

"THE BYTECODE VAULT" is the giveaway — this isn't a plain string-compare crackme, it's a small **custom bytecode VM** embedded in the binary.

## 2. Static Analysis

The whole checker lives in one compact function. Structurally it's built from four pieces:

### 2.1 Obfuscated opcode stream

A 4-byte "program" sits in `.rodata` at a fixed offset, XOR-encoded with a **rolling key** that starts at `0xa5` and increases by `0x11` (17) every byte. Decoding it by hand:

```
raw: b4 81 ac 38
key: a5 b6 c7 d8
     -----------
     11 37 6b e0
```

So the VM's "program" is the 4-opcode sequence `0x11 → 0x37 → 0x6b → 0xe0`. A dispatcher loop reads/decodes one opcode per iteration and stops once the rolling key reaches `0xe9`.

### 2.2 What each opcode does

|Opcode|Role|
|---|---|
|`0x11`|Length gate: sets a running "all-checks-passed" flag to `(input_length == 50)`.|
|`0x37`|Length gate again (hard reject if `!= 50`), then runs **Loop 1**: builds a 50-byte scratch table from the user's input.|
|`0x6b`|Runs **Loop 2**: compares a second embedded (also XOR-encoded) 50-byte table against the scratch table, AND-accumulating into the pass/fail flag.|
|`0xe0`|Final check: if the accumulated flag is non-zero → `"Access granted."`, else `"Access denied."`|

So the actual cryptographic work is entirely in Loop 1 and Loop 2.

### 2.3 Loop 1 — encoding the input (opcode `0x37`)

For each input position `i` (0..49):

```
addend(i) = ((11*i) mod 256) XOR 0x17
K(i)      = (65 + 29*i) mod 256
R(i)      = (i mod 7) + 1
stored[slot(i)] = ( addend(i) + ROL8( input[i] XOR K(i), R(i) ) ) mod 256
```

where `slot(i) = (17*i) mod 50` — a reciprocal-division trick (`mul` by a magic constant + shifts) is used in the disassembly to compute this modulo, which is the classic compiler-idiom pattern for constant-divisor remainder.

### 2.4 Loop 2 — the comparison (opcode `0x6b`)

A second embedded 50-byte table (separately XOR-encoded, rolling key starting at `0x44`, `+13` per byte) is decoded and compared position-by-position:

```
K2(n)        = (68 + 13*n) mod 256
expected[n]  = table_B_raw[n] XOR K2(n)
check: expected[n] == stored[slot2(n)]     where slot2(n) = (17*n) mod 50
```

### 2.5 The shuffle cancels itself out

At first glance `slot(i) = (17*i) mod 50` looks like a deliberate permutation meant to scramble which input character influences which comparison — a common technique to make a checker resistant to naive per-character brute-forcing. But **both loops use the exact same formula on the same loop variable**: Loop 1 writes to `slot(i)` while building from input position `i`, and Loop 2 reads from `slot2(n) = slot(n)` while checking against expected position `n`. Since `i ↦ (17i) mod 50` is a bijection (`gcd(17,50)=1`), the only `i` that ever lands in `slot(n)` is `i = n` itself. The shuffle is real machinery, but it's _self-cancelling_: position `n` of the expected table always ends up compared against position `n` of the input, transformed. Effectively:

```
expected[n] == addend(n) + ROL8( input[n] XOR K(n), R(n) )   (mod 256)
```

a simple, fully-invertible per-character transform with constants that depend only on the index `n` — not on the input at all.

## 3. Solving

Because every quantity except `input[n]` is directly computable from `n`, the transform inverts cleanly with no brute force required:

```python
def ror8(x, r):
    r %= 8
    return ((x >> r) | (x << (8 - r))) & 0xff

for n in range(50):
    addend = ((11*n) % 256) ^ 0x17
    K      = (65 + 29*n) % 256
    R      = (n % 7) + 1
    K2     = (68 + 13*n) % 256
    expected = table_B_raw[n] ^ K2

    rotated_val   = (expected - addend) % 256
    input_xor_K   = ror8(rotated_val, R)
    input[n]      = input_xor_K ^ K
```

Running this against the two extracted embedded tables produced, character by character, a clean printable ASCII string on the first try — strong confirmation the reversing was correct (garbage output would have meant a sign or off-by-one error somewhere in the index/rotation math).

## 4. Verification

```
$ printf "BDSEC{c0nTr0L_fl0w_1s_4_l13_bUt_bYt3c0d3_d03s_n0t}\n" | ./vault
...
Enter the flag:
[+] Access granted.
```

## 5. Flag

```
BDSEC{c0nTr0L_fl0w_1s_4_l13_bUt_bYt3c0d3_d03s_n0t}
```

Fittingly self-referential — the flag literally describes the bug class: the _control flow_ (which opcode runs, in what order) is easy to obfuscate and looks scary, but the _bytecode's data transform_ was fully linear and invertible once traced through.

## 6. Takeaways

- A custom-VM crackme is really just "how many layers of indirection stand between me and a linear/invertible transform." Trace the dispatcher once, then focus entirely on the arithmetic inside each handler.
- Reciprocal-division idioms (`mul` by a big odd constant + `shr`) in disassembly are almost always the compiler's way of computing `x mod k` or `x / k` for a constant `k` — recognizing the pattern (and just testing candidate `k` values numerically) is faster than deriving the magic constant by hand.
- Index permutations that are applied identically on both the "write" and "read" side of a comparison don't add real security — always check whether a shuffle is _actually_ mixing information across positions, or just relabeling the same position twice.
- When a transform is provably a function of the position index and the unknown input byte only (no cross-character dependencies), it's directly invertible — no need to brute-force 256 values per character.

---

_Obito Uchiha — Team AKATSUKI_
