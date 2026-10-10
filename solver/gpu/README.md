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
