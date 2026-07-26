# Broken Printer — BDSec CTF 2026 (Rev, 430 pts)

**Flag:** `BDSEC{th3_pr1nt3r_d03s_n0t_pr1nt_1n_0rd3r}`

## Challenge

A stripped 64-bit PIE ELF (`broken_printer`) is served over `nc 45.56.67.129 24873`. On connection it reads a local `flag.txt`, prints an ASCII-art "printer" banner, a `job id`, a `paper width`, and then a long string of scrambled-looking punctuation (`. : + # | / ~`), followed by warnings that "output order may be incorrect" and "foreign ink [was] detected in every block." No input is ever read from the socket — the binary just dumps this output and closes.

## Static analysis

Disassembling and decompiling `main` (Ghidra) shows the program:

1. Reads up to 96 bytes from `flag.txt`, strips the trailing newline — call the resulting length `N` ("paper width").
2. Computes a 32-bit seed:
    
    ```c
    seed = lowbias32( getpid()*0x9e3779b9 ^ (tv_nsec ^ tv_sec) )
    ```
    
    `lowbias32` is Chris Wellons' well-known bias-free integer hash (`x^=x>>16; x*=0x7feb352d; x^=x>>15; x*=0x846ca68b; x^=x>>16;`).
3. **This seed is printed verbatim as the `job id`.** That's the whole bug — the "randomness" behind the scrambling is handed to the client in cleartext.
4. Picks a stride `step`: the first prime from `[5,7,11,13,17,19,23,29,31]` that does **not** divide `N` (guarantees `step` is coprime to `N`).
5. For each byte `i` of the flag (`0..N-1`):
    - Splits the byte into four 2-bit digits (MSB→LSB) and maps each through a 4-symbol alphabet `. : + #`.
    - Cyclically rotates those four digits by `i mod 4`.
    - Computes a second, independent hash `h = lowbias32((i * 0x45d9f3b) ^ seed)` and inserts one extra "decoy" symbol from the same 4-symbol alphabet at slot `h % 5` — this 5th symbol carries no information, it's pure noise.
    - If `i` is odd, reverses the resulting 5-symbol block (swap slot 0↔4, 1↔3; middle slot untouched).
    - Writes the block to output slot `(idx0 + i*step) mod N`, where `idx0` comes from an earlier stage of the _same_ seed hash.
6. Prints the `N` blocks in slot order, joined by a single decorative separator character (`| / ~`) between blocks (none after the last) — giving a total output length of exactly `6N - 1`.

Because `step` is coprime to `N`, `slot = (idx0 + i*step) mod N` is a bijection — every original byte lands in exactly one output slot, it's just not slot `i`.

## Why this is solvable without touching the target further

Every step above is a pure function of `(i, N, seed)` — **never** of neighboring byte values. And `seed` is printed as the job id. So:

- `step` and `idx0` are recomputable directly from `N` and `seed`.
- For each `i`, the decoy slot `h % 5` is recomputable the same way, so the 4 real digit-symbols can be picked out of the 5-symbol block deterministically.
- Undoing the `i mod 4` rotation and the odd-`i` reversal is just index arithmetic.
- Mapping symbols back to bits via the same 4-symbol alphabet reconstructs the original byte exactly.

No brute force, no dynamic re-execution of the binary, and no leftover uncertainty — the whole flag falls out of one pass of arithmetic.

One subtlety that cost an early wrong attempt: naively assuming "each output block only depends on its own byte value" and testing candidate bytes against a black-box oracle (same byte repeated everywhere) looked plausible but silently ignored the decoy-symbol insertion and the odd/even reversal, so it degraded after the first couple of characters. Getting the decompiled pseudocode of `main` and reading the actual block-construction loop is what exposed the real structure.

## Solve script

```python
TABLE4 = ['.', ':', '+', '#']
INV4 = {c: i for i, c in enumerate(TABLE4)}
MASK32 = 0xFFFFFFFF

def lowbias32(x):
    x &= MASK32
    x ^= x >> 16
    x = (x * 0x7feb352d) & MASK32
    x ^= x >> 15
    x = (x * 0x846ca68b) & MASK32
    x ^= x >> 16
    return x

def invert_xorshift16(y):        # undo the final x^=x>>16 of the seed hash
    y &= MASK32
    hi = y >> 16
    lo = (y & 0xFFFF) ^ hi
    return (hi << 16) | lo

def find_step(n):
    for p in [5,7,11,13,17,19,23,29,31]:
        if n % p != 0:
            return p
    return 1

def decode(job_id_hex, n, body):
    seed = int(job_id_hex, 16)
    idx0 = (invert_xorshift16(seed) >> 16) % n
    step = find_step(n)
    blocks = [list(body[6*p:6*p+5]) for p in range(n)]

    out = []
    for i in range(n):
        blk = blocks[(idx0 + i*step) % n][:]
        if i % 2:
            blk[0], blk[4] = blk[4], blk[0]
            blk[1], blk[3] = blk[3], blk[1]

        h = lowbias32(((i * 0x45d9f3b) & MASK32) ^ seed)
        decoy = h % 5
        d = [blk[s] for s in range(5) if s != decoy]
        digit = [d[(m - i) % 4] for m in range(4)]

        bits = [INV4[c] for c in digit]
        out.append(chr((bits[0]<<6)|(bits[1]<<4)|(bits[2]<<2)|bits[3]))
    return "".join(out)
```

Run against the captured `job id`, `paper width`, and scrambled body from `nc 45.56.67.129 24873` → recovers the flag directly.

## Flag

```
BDSEC{th3_pr1nt3r_d03s_n0t_pr1nt_1n_0rd3r}
```
