# GPU search for the old-Electrum seed

Searches for an **old Electrum (v1)** seed embedded in the article *Securing
Wealth in Poetry*, targeting `1K4ezpLybootYF23TM4a8Y4NyP7auysnRo`.

## Why this hypothesis

The article prints an example seed phrase:

```
witch collapse practice feed shame open despair creek road again ice least
```

`witch`, `collapse`, `shame` and `least` are **not in the BIP39 wordlist** — so
this is not a BIP39 phrase — but all 12 words **are** in the 1626-word **old
Electrum v1** list. That is direct evidence the author was working with
Electrum, while six years of community attempts assumed BIP39.

It also resolves a structural problem. The embedding method is positional, so
every seed word must fall in a fixed window of the carrier text. Under BIP39
some of those windows in the article's prose contain **no BIP39 word at all**
(words 1–9 of the Revolution story are *My grandfather known to me as ye-ye was
born* — none are BIP39), which makes a BIP39 embedding impossible there. Under
the Electrum list every window is populated, so the same text **is** feasible.

## What is searched

The article documents the rule:

> every digit read increases by ten, so 21.493021 translates to:
> 2, 11, 24, 39, 43, 50, 62, 71

i.e. for the *j*-th digit of a landmark's GPS coordinates,

```
position_j = digit_j + 10*j        (1-indexed word position in the carrier)
```

Verified against the article's own worked example: Supreme Court
`38.8906 N, 77.0044 W` → positions `3,18,28,39,40,56,67,77,80,90,104,114`,
exactly the list the article prints.

Because `digit_j ∈ [0,9]`, word *j* must lie in the decade window
`[10j, 10j+9]`. So **enumerating all decade-consistent combinations covers
every possible landmark on Earth at once** — no coordinate guessing needed.
The search sweeps 88 carrier × tokenization configurations (whole article,
body, sections, the Revolution story, every individual paragraph; punctuation
and hyphen and numeral handling varied) at every story-start offset.

```
feasible work units : 26,574
total candidates    : 2,863,703,783
```

## Why a GPU

Electrum v1 derives the master key by stretching the seed through **100,000
iterations of SHA256(x ‖ seed)**. That is ~44 ms per candidate on a CPU core,
but candidates are completely independent, so a GPU runs thousands at once.

| | rate | time for 2.86 B |
|---|---|---|
| 4 CPU cores | ~90 /s | ~10,000 h (hopeless) |
| modest GPU | ~5,000 /s | ~6.6 days |
| RTX 3060-class | ~10,000–20,000 /s | **1.7–3.3 days** |
| RTX 4090-class | ~40,000 /s | **~20 h** |

Split of work: the GPU does the stretch (>99% of the cost); the CPU does
candidate generation plus secp256k1 + hash160 + base58 per candidate.

## Install

```bash
pip install pyopencl numpy coincurve
```

OpenCL works on NVIDIA, AMD and Intel GPUs — NVIDIA ships OpenCL in its normal
driver, so no CUDA toolkit is needed. If you have no GPU driver ICD and just
want to test, `pip install pocl-binary-distribution` gives a CPU OpenCL device.

## Run

```bash
# 1. ALWAYS do this first. It is refused to --run until this passes.
python electrum_gpu_search.py --selftest

# 2. See your hardware's real throughput and pick --addrs/--procs
python electrum_gpu_search.py --bench --batch 16384

# 3. See the space and your ETA
python electrum_gpu_search.py --plan

# 4. Go
python electrum_gpu_search.py --run --batch 32768
```

Useful flags:

| flag | meaning |
|---|---|
| `--list-devices`, `--device N` | pick the GPU |
| `--batch N` | candidates per GPU dispatch; raise it until throughput plateaus |
| `--chunk-iters N` | stretch rounds per kernel launch (must divide 100000). **Lower this (e.g. 2500) if the kernel is killed on a GPU that also drives your display** — Windows' TDR watchdog aborts kernels running ~2 s. |
| `--procs N` | CPU processes for the EC/address stage |
| `--addrs N` / `--changes N` | addresses checked per candidate (default 3 × 2 = 6). Lowering to `--addrs 1 --changes 1` makes the CPU stage ~6× cheaper if it is your bottleneck. |
| `--compressed` | also test compressed keys (Electrum v1 used **un**compressed, so off by default) |
| `--shard i/N` | split the work across several GPUs or machines |

Progress is checkpointed atomically to `progress.json`, so you can stop with
Ctrl-C and resume by re-running the same command. Work units are ordered
cheapest-first. A hit is printed loudly and appended to `FOUND.txt`.

## Correctness

`--selftest` is not decorative — a silent kernel bug would waste days, so the
script refuses to `--run` until it passes. It checks:

1. the CPU reference path reproduces Electrum's own v1 test vector
   (`powerful random nobody …` → mpk `e9d4b786…42b3`, address 0
   `1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo`);
2. the **GPU** stretch output is byte-identical to CPU `hashlib` for that seed,
   and that it yields the same master public key and address 0;
3. GPU and CPU agree on a batch of 8 random seeds.

All three were run and passed here on a CPU OpenCL device, so the kernel logic
is validated; `--selftest` re-validates it on your actual GPU.

One deliberate filter: a candidate is skipped unless its Electrum
`mnemonic_decode` yields exactly 32 hex characters. A seed Electrum itself
generated always does (it encodes a 128-bit value), so this is a correctness
condition rather than a shortcut — it also keeps every SHA256 message exactly
64 bytes, which the kernel assumes. It drops ~0.38% of arbitrary 12-word
combinations, none of which could be a genuine Electrum seed.

## If it finds nothing

That result is still worth having: it would close the GPS/decade model for
Electrum v1 completely, leaving the "Story & phone number" method, whose
positional key the article deliberately never publishes ("These should be
written on a different page to remove any connection between the text and the
numbers") — see `../FINDINGS.md`. Note the closing hint promises every
**word**, never the numbers.

---

# `phone_gpu_search.py` — the phone-method search

**This is now the better-motivated target.** See `../FINDINGS.md` §7–8.

The article's "Story & phone number" method keeps its positional key off the
page by design — *"These should be written on a different page to remove any
connection between the text and the numbers"* — so the key is not recoverable
from the article and brute-forcing the positions is the intended path. The
closing hint fits exactly: it promises every **word**, never the numbers.

The carrier is one of the two worked examples, the only purpose-written,
seed-dense texts in the article (41% and 29% BIP39 words, versus 19% for the
article's natural prose). The phone example is the prime suspect: densest, the
method says it holds "true and decoy seed phrases", and its own published
numbers decode to an *invalid* phrase, marking the published reading as a decoy.

And the author's own tooling is BIP39, not Electrum: the GPS example, which he
wrote himself, is a 12-word BIP39 mnemonic with a **valid checksum**. (The
printed `witch collapse …` phrase is an Electrum-wordlist phrase, but GitHub
code search finds it in 309 files — it is a stock sample he pasted, so it says
nothing about his own wallet. That is why this tool, not the Electrum one, is
the priority.)

## Slices

Positions are a greedy ascending read of the concatenated phone digits, so the
12 positions' **total digit count** equals the digits of 2–3 phone numbers —
verified on the published example (24 digits = two 12-digit numbers). That is
the prune.

```
 #  carrier        slice                              combos     cksum-valid
 0  GPS example    3 phones (30-39 digits)         9,238,671         577,417
 1  GPS example    24 digits                     214,526,520      13,407,908
 2  GPS example    2 phones (20-26 digits)     1,208,613,315      75,538,332
 3  phone example  3 phones (30-39 digits)       958,995,275      59,937,205
 4  phone example  24 digits (as published)   26,640,902,470   1,665,056,404
 5  phone example  2 phones (20-26 digits)  117,873,413,580   7,367,088,349
```

Slice 0 has already been run to completion on CPU: 9,238,671 combinations,
**no hit**. Slice 4 is the default and the most faithful to the published
example.

## How the work is split

Enumerating 26.6 billion 12-subsets in Python is hopeless (~5 µs each is 37
CPU-days), so the enumeration goes on the GPU too:

| stage | where | what |
|---|---|---|
| kernel 1 | GPU | combinatorial unranking → 12 word indices → BIP39 checksum test; the 1/16 survivors are compacted with an atomic counter, so the host never sees the rest |
| kernel 2 | GPU | PBKDF2-HMAC-SHA512(mnemonic, `mnemonic`, 2048). The HMAC key schedule is hoisted out of the loop, so each iteration is exactly 2 SHA-512 compressions |
| CPU | host | BIP32 `m/44'/0'/0'/0/0` + secp256k1 + hash160, survivors only |

**The CPU stage is usually the limiter**: that path needs 3 EC multiplies
(~180 µs), so ~5.5k/s per core — roughly 88k/s on 16 cores, which puts slice 4
at about 5–6 hours. `--bench` prints your real numbers for both stages; if the
CPU figure is the smaller one, more cores or `--shard i/N` across machines is
what helps.

## Run

```bash
pip install pyopencl numpy coincurve

python phone_gpu_search.py --selftest          # required; --run is refused without it
python phone_gpu_search.py --list
python phone_gpu_search.py --bench
python phone_gpu_search.py --run --slice 4
python phone_gpu_search.py --run --slice 4 --shard 0/4
```

Checkpointed atomically per profile to `phone_progress.json`; re-run the same
command to resume. Hits go to `FOUND.txt` and are printed loudly.

## Correctness

`--selftest` was run here against a CPU OpenCL device (pocl) and passed:

```
known-good GPS reading reproduced   OK
its BIP39 checksum is valid         OK
kernel2 PBKDF2 vs hashlib           OK      <- byte-identical
kernel2 on 16 random mnemonics      OK
kernel1 unrank+checksum: gpu=1114 ref=1114 OK
```

Kernel 1 is checked against a pure-Python enumeration over 20,000 combinations
(identical survivor sets), and kernel 2 against `hashlib.pbkdf2_hmac`. The
CPU-side reference implementation of the same search is `../subset_phone.py`,
whose enumerator independently reproduces the known-good GPS reading and whose
task decomposition provably covers the exact expected combinatorial count — use
it to cross-check any result.

## Caveat worth knowing

Both solvers filter on a valid BIP39 checksum, which assumes the author's seed
is a well-formed mnemonic. He published a non-BIP39 phrase while calling it
"BIP-39", so that assumption is not certain; dropping it multiplies every count
above by 16.
