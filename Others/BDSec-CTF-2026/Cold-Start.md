# Cold Start — Writeup

**Category:** Reverse Engineering **Points:** 495 **Author:** NomanProdhan **Flag:** `BDSEC{th3_k3y_w4s_s0m3wh3r3_1n_16_m1ll10n}`

## Challenge

We're given a single file, `cold_start.bdsec`, described as a system that "lost its activation seed during shutdown." We need to recover the seed and restore the boot sequence.

## Initial Triage

```
$ file cold_start.bdsec
cold_start.bdsec: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

It's a stripped, dynamically linked PIE binary. Running `strings` on it reveals the interactive prompt:

```
========================================
               COLD START
========================================
The system was powered down unexpectedly.
activation seed>
System restored.
Boot sequence rejected.
```

So the binary prompts for an "activation seed," validates it, and either prints a success message (with the flag) or rejects it.

## Static Analysis

Disassembling with `objdump -d -M intel` and walking the main function (`0x10d0`) shows the following input validation:

1. `fgets` reads up to 0x40 bytes, `strcspn` strips the trailing newline.
2. `strlen(input) == 6` is required — the seed must be exactly 6 characters.
3. Every character is checked against `isxdigit` via `__ctype_b_loc` — the seed must be a 6-character hex string.
4. `strtoul(input, &end, 16)` parses it as a hex value into `ebp`.
5. The parsed value is checked: `ebp <= 0xffffff` — i.e. it must fit in 24 bits (which is guaranteed anyway by 6 hex digits, but confirms the valid range is `0x000000`–`0xffffff`, about **16.7 million** values).

### The core routine

Once `ebp` (the seed) passes validation, the binary runs a tight loop (`0x120f`–`0x132e`) 96 times, building a `uint32_t arr[96]` array. Each iteration mixes together:

- A running state carried in `edi`, `edx`, `r8d`, `r9d`, `r10d`, `r11d`.
- A 256-entry × 4-byte lookup table embedded in `.rodata` at `0x2140` (effectively a custom S-box), indexed by single bytes derived from the running state.
- Constants lifted from well-known hash/PRNG algorithms, reused here as generic mixing constants rather than in their original algorithms:
    - `0x9e3779b1` / `0x1b873593` — Fibonacci-hashing / MurmurHash3-style constants
    - `0x811c9dc5` (FNV offset basis) and `0x1000193` (FNV prime) — FNV-1a mixing
    - `0x7feb352d` / `0x846ca68b` — a MurmurHash-style `fmix32` avalanche finisher
    - `0x45d9f3b`, `0x27d4eb2d`, `0x61c88647` — fixed per-iteration increments
    - A 64-bit magic constant (`0x4ec4ec4ec4ec4ec5`) used to compute `i % 13` without a division instruction

After the 96-word array is generated, eight specific words are pulled out (indices **7, 11, 23, 47, 55, 68, 83, 91**), combined with the final loop state and the seed itself, and run through the `fmix32`-style avalanche finisher. The results are compared against three hardcoded constants:

```
(mix1 & 0xffff) == 0x9c8c
mix2            == 0x91e50c54
mix3            == 0xc2e4f8bd
```

All three must match for the check to succeed — otherwise the program prints `Boot sequence rejected.` and exits.

There is no way to invert this analytically (it's a one-way avalanche mix over an 8-word subset of a 96-word keystream), and the constants give no direct hint about the seed. However, the seed space is bounded to `0x000000`–`0xffffff` — only **16,777,216** possibilities — which is small enough to brute-force if the check itself is implemented natively instead of run through a fresh process each time.

## Approach: Native Brute Force

Rather than re-launching the target binary 16.7 million times (far too slow), I mechanically translated the loop and the final comparison directly from the disassembly into equivalent C, instruction-by-instruction, including:

- Extracting the embedded 256-entry S-box from the binary's `.rodata` section (file offset `0x2140`, matching its virtual address since the section is loaded 1:1).
- Reproducing every register operation (rotates, FNV multiply, table lookups, the `i % 13` magic-number trick, etc.) faithfully so the output is bit-for-bit identical to the real binary.
- Looping the seed from `0` to `0xffffff` and testing all three comparisons for each candidate.

Compiled with `-O2`, this runs in a couple of seconds and reports a single matching seed:

```
FOUND seed = 9684900 (0x93c7a4)
```

## Verification

Feeding that value back into the real, unmodified binary confirms it:

```
$ printf "93c7a4\n" | ./cold_start
========================================
               COLD START
========================================
The system was powered down unexpectedly.

activation seed> System restored.
BDSEC{th3_k3y_w4s_s0m3wh3r3_1n_16_m1ll10n}
```

## Flag

```
BDSEC{th3_k3y_w4s_s0m3wh3r3_1n_16_m1ll10n}
```

Fittingly, the flag itself confirms the intended solve path — the key really was "somewhere in 16 million," i.e. a brute-forceable 24-bit search space once the validation routine is understood well enough to reimplement natively.

## Takeaways

- A stripped binary with a heavy custom "hash" isn't necessarily meant to be inverted mathematically — check the bounded input space first. 6 hex digits capped at `0xffffff` was the tell that brute force was the intended path.
- When brute-forcing, re-executing the target process per guess is usually too slow for search spaces beyond a few hundred thousand; porting the exact check into native code (matching the disassembly mechanically, instruction-by-instruction, rather than trying to "simplify" the algorithm) is faster and less error-prone than reasoning about what the mixing function "means."
- Recognizing borrowed constants (FNV, MurmurHash's `fmix32`, Fibonacci hashing) helped identify which parts of the routine were standard mixing steps versus custom logic, without needing to know the exact algorithm being imitated.

- ---

_Obito Uchiha — Team AKATSUKI_
