# Borrowed Memory — BDSEC CTF 2026

**Category:** Reverse Engineering / Pwn **Points:** 190 **Author:** NomanProdhan **Flag:** `BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}`

---

## 1. Recon

The challenge was distributed as `borrowed_memory.bdsec` with the description _"Memory can be borrowed right?"_. The custom extension is a red herring:

```
$ file borrowed_memory.bdsec
borrowed_memory.bdsec: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

It's a stripped, PIE, dynamically linked x86-64 ELF — the `.bdsec` extension does nothing to the actual file format.

```
$ checksec chall
RELRO:      Partial RELRO
Canary:     Found
NX:         Enabled
PIE:        Enabled
```

Given the security mitigations and stripped symbols, this pointed toward a logic/reversing puzzle rather than a straightforward memory-corruption pwn.

## 2. Static Analysis

`strings` revealed an ASCII banner and two key output strings:

```
BORROWED MEMORY
0x???? -> 0x???? -> 0x????
Return what was borrowed.
rejected
```

The `0x???? -> 0x???? -> 0x????` hint plus the challenge title "Borrowed Memory" strongly suggested the program wants a **chain of memory addresses/offsets** as input — like following a linked list of "borrowed" pointers.

Disassembling with `objdump -d -M intel` showed the entire logic lives in one large `main`-equivalent function (`.text` at `0x10c0`). Breaking it down:

### 2.1 Keystream generation (startup)

On startup the binary fills a 2048-byte (`0x800`) buffer in `.bss` using a xorshift-style byte PRNG seeded with a fixed constant (`0x91e10da5`). This buffer acts as a keystream/lookup table used later during flag generation.

### 2.2 Input loop — 12 rounds

The program prints `>` , reads **one line at a time** (not all 12 numbers on one line — an early mistake I made), and parses exactly one number via `strtoul` with base 0 (so both `0x...` hex and decimal work). Each parsed value must satisfy:

```
0x4000 <= value <= 0x47FF
```

i.e. it fits in an 11-bit offset added to a `0x4000` base — literal "addresses" being "returned/borrowed". This repeats **12 times**, storing each 16-bit value into a stack array.

### 2.3 The verification / hash chain

After all 12 numbers are collected, a second loop walks the stack array and, for each entry:

1. Computes an **internal running state** `si`, seeded from a value baked into `.data` (`0x7d95`) XORed with a constant (`0x7c31`), giving an initial `si = 0x01A4`.
2. Compares the _user-supplied_ word against `si + 0x4000`. If they don't match exactly → `rejected`.
3. If they match, it derives the **next** `si` using a chain of XOR/ROL operations mixed with lookups into the 2048-byte keystream table (very reminiscent of a Tiny-Encryption-Algorithm-style round, complete with the `0x9e3779b9` golden-ratio constant and a SHA-256-like IV `0x6a09e667` used purely as noise/constants).
4. It also emits one output byte per round (derived only from the internal `si`/state — not from the register holding the user's number) into a 12-byte staging buffer.

Crucially: **the register holding the user's entered number is only used for the equality gate.** The actual next-state computation and the 12-byte staging buffer come from the _value already stored in memory_ — which matters for the exploitation step below.

### 2.4 Flag construction

A final loop runs 40 times, mixing:

- the 2048-byte keystream table,
- the 12-byte staging buffer produced above,
- and — critically — **reads the original 12 words directly back out of stack memory** (not from any register) as additional key material,

to produce and print the 40-character flag.

## 3. Exploitation Strategy

Since the "correct" sequence of 12 chain values is **fully deterministic** (computed purely from constants embedded in the binary — no external secret), the goal was simply to **compute what that unique valid chain is**, then supply it as real input.

Manually re-implementing every XOR/ROL/multiply-by-reciprocal trick in Python by hand was error-prone, so instead I let the binary compute its own expected values for me:

### 3.1 Extracting the chain with GDB scripting

I wrote a GDB Python script that:

1. Loads the binary and does a dry `starti` to resolve the PIE load base (ASLR is disabled by default under `gdb`, so the base is deterministic).
2. Sets a breakpoint at the `cmp r8w, ax` instruction (the exact comparison between the user's entered word and the internally computed expected value).
3. Feeds 12 placeholder lines (`0x4000` x 12) as stdin so the program reaches the check loop without getting rejected at the format stage.
4. On each of the 12 breakpoint hits, reads the `ax` register (the _expected_ value for that round), records it, force-sets `r8` to match so execution proceeds to the next round, and continues.

This produced the unique required chain:

```
0x41a4, 0x42f0, 0x4143, 0x436c, 0x421d, 0x44a8,
0x40f6, 0x455b, 0x4317, 0x468c, 0x425a, 0x473d
```

### 3.2 First attempt — garbage output

Continuing execution after forcing all 12 register comparisons produced garbage bytes instead of a flag. Root cause: as noted in §2.4, the final flag-generation loop reads the **actual stack memory** holding the entered numbers — not the register I had patched. Since I never sent the real values over stdin, memory still held the `0x4000` placeholders, so the flag routine mixed in the wrong key material.

### 3.3 Second attempt — real input, no patching needed

Once the correct chain was known, I simply fed it as genuine stdin input (12 lines, one value each) with **no GDB tricks required** — the checks all pass naturally since the values _are_ correct:

```
$ ./chall < real_input.txt
...
> > > > > > > > > > > >
[+] BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}
```

## 4. Flag

```
BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}
```

## 5. Takeaways

- Custom/odd file extensions are cosmetic — always run `file` first.
- When a "check" loop rejects immediately, verify the actual **I/O framing** (one line vs. many tokens per line) before assuming the logic is wrong.
- A comparison gate and the data actually consumed downstream can live in _different_ storage locations (register vs. memory) — bypassing a register-level check doesn't guarantee the "real" data used later is also correct. Always trace where **all** downstream computations pull their operands from.
- GDB scripting is a fast way to let a deterministic, secret-free hash chain "compute itself" instead of hand-transcribing obfuscated arithmetic.

---

_Obito Uchiha — Team AKATSUKI_
