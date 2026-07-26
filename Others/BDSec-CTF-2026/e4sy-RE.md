# e4sy RE — BDSec CTF 2026

**Category:** Reverse Engineering **Points:** 125 **Author:** NomanProdhan **Solved by:** Obito Uchiha — Team AKATSUKI

---

## Challenge Description

> An easy RE challenge for you. Crack it. Flag Format: `BDSEC{s0mething_here}`

We're given a single file: `e4sy_RE.bdsec`.

## Initial Recon

```bash
$ file e4sy_RE.bdsec
e4sy_RE.bdsec: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

A normal, unstripped x86-64 PIE binary. Since it's not stripped, symbol names survive — this makes static analysis much easier.

```bash
$ strings -n 6 e4sy_RE.bdsec
...
[+] Excellent work, reverse engineer!
[+] Submit the flag to the CTF platform to receive your points.
[+] Congratulations! You found a flag!
[+] Nice reversing work. Keep exploring the binary...
[-] The binary still has secrets to reveal.
Enter the flag:
[-] Incorrect flag.
...
challenge.c
expected.0 / expected.1 / expected.2 / expected.3
key_part_a.5 / key_part_b.4
```

Two things stand out immediately:

1. There are **two different "success" messages** — `"Excellent work, reverse engineer!"` and `"Congratulations! You found a flag!"`. That's a strong hint that some success paths are decoys.
2. There are **four `expected` arrays** (`expected.0` .. `expected.3`) and two key arrays (`key_part_a`, `key_part_b`). Multiple expected buffers usually means multiple input-length branches — classic rabbit-hole design.

## Static Analysis — `main()`

Disassembling `main` (objdump, Intel syntax) shows the program:

1. Seeds `rand()` with `time() ^ clock()` and prints a "lucky number" — **cosmetic only**, it's never used in the flag check. Red herring.
2. Reads a line with `fgets`, strips the trailing newline with `strcspn`.
3. Branches **purely on the stripped input length** (`rcx`):

| Input length    | Branch target | Expected buffer           | Outcome message                                |
| --------------- | ------------- | ------------------------- | ---------------------------------------------- |
| 24 (`0x18`)     | `main+0x4f1`  | `expected.0`              | "Congratulations!" (decoy)                     |
| 26 (`0x1a`)     | `main+0x410`  | `expected.1`              | "Congratulations!" (decoy)                     |
| 29 (`0x1d`)     | `main+0x102`  | `expected.2`              | "Congratulations!" (decoy)                     |
| **41 (`0x29`)** | `main+0x21b`  | `expected.3` + key blocks | **"Excellent work, reverse engineer!" (real)** |

Only the **41-character** path leads to the genuine success message that tells you to submit the flag. The other three lengths are deliberately plausible-looking (`BDSEC{...}` at 24/26/29 chars all "look real") but are dead ends built to burn your time. Since `BDSEC{}` itself is 7 characters, the real flag has a **34-character** inner content.

## Reversing the Real Check (41-byte path)

The core loop (`main+0x21b` onward) does the following for every byte `i = 0 .. 40` of the input:

```text
key    = key_part_a[i % 8] ^ key_part_b[i % 8] ^ input[i]
key    = rol8(key, (i % 7) + 1)          ; 8-bit rotate-left
key    = (key + ((11*i) ^ 0x23)) & 0xFF  ; byte-wise add
output[(13*i) % 41] = key
```

- `key_part_a` / `key_part_b` are two 8-byte constants XORed together as a rolling keystream (repeating every 8 bytes).
- The rotate amount cycles `1,2,3,4,5,6,7,1,2,...` (`(i % 7) + 1`).
- The additive term `(11*i) ^ 0x23` changes every byte, killing simple frequency analysis.
- Crucially, the output isn't written in order — it's **scattered** into `output[(13*i) % 41]`. Since `gcd(13, 41) = 1`, this is a full permutation of positions 0–40, so every input byte lands in a unique output slot, just shuffled.

The scrambled 41-byte `output` buffer is then compared (via SSE `pxor` + horizontal-OR reduction, plus a small tail loop) against a hardcoded constant assembled from three memory regions:

- `output[0:16]` must equal the 16 bytes at `key_part_a.5 + 0x8` (label `+0x460` in `.rodata`)
- `output[16:32]` must equal the next 16 bytes (`.rodata+0x470`)
- `output[32:41]` must equal 9 bytes from `expected.3 + 0x20`

Reading these straight out of `.rodata`:

```
block1 (16 bytes): 23 05 79 1b 6c c1 84 0f 88 b2 7d eb a0 7e f4 32
block2 (16 bytes): c6 f5 70 c1 c5 26 bf 16 dd 42 36 3a 6a 6a 45 17
block3 ( 9 bytes): f4 4c cd 84 ae 27 8c c8 38

key_part_a (8B): 19 a4 c7 52 6e 01 9b f0
key_part_b (8B): 5b 75 b4 7b cb 5d 73 e6
```

## Inverting the Transform

Each step is trivially invertible, so we just walk it backwards for every output index:

```python
def rol8(v, r):
    r %= 8
    return ((v << r) | (v >> (8 - r))) & 0xFF

def ror8(v, r):
    r %= 8
    return ((v >> r) | (v << (8 - r))) & 0xFF

key_a = bytes.fromhex("19a4c7526e019bf0")
key_b = bytes.fromhex("5b75b47bcb5d73e6")

expected = bytes.fromhex(
    "2305791b6cc1840f88b27deba07ef432"   # block1
    "c6f570c1c526bf16dd42363a6a6a4517"   # block2
    "f44ccd84ae278cc838"                 # block3
)

flag = [0] * 41
for i in range(41):
    pos = (13 * i) % 41
    out = expected[pos]
    addval = ((11 * i) ^ 0x23) & 0xFF
    val = (out - addval) & 0xFF          # undo the add
    val = ror8(val, (i % 7) + 1)         # undo the rotate
    flag[i] = val ^ key_a[i % 8] ^ key_b[i % 8]  # undo the xor keystream

print(bytes(flag).decode())
```

**Output:**

```
BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}
```

## Verification

Ran the recovered string forward through the _same_ forward transform used in the binary and confirmed the scrambled output matches the embedded constant byte-for-byte — confirming the flag before submission (also sanity-checked against the live binary, which now prints `[+] Excellent work, reverse engineer!`).

## Flag

```
BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}
```

## Key Takeaways

- When a binary has **multiple "expected" buffers keyed off input length**, don't chase the first branch that prints something success-shaped — check _which_ success message is the real one (here, two nearly-identical "congrats" strings existed specifically to bait a wrong length).
- `rand()`/`time()`/`clock()` calls that only feed a cosmetic printf (the "lucky number") are worth spotting early and ruling out as red herrings.
- Permutation via `(13*i) % 41` (coprime modulus) is just an obfuscation layer, not real security — once you have the per-byte formula, inverting a bijective scatter is straightforward.
- SIMD (`pxor`/`psrldq`/`por`) comparison chains that "OR-reduce" 16 bytes down to a single register are just a vectorized `memcmp` — mentally treat them as byte-for-byte equality checks against the XOR key.

---

_Obito Uchiha — Team AKATSUKI_
