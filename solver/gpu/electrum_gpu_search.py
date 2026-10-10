#!/usr/bin/env python3
"""
GPU search for an old-Electrum (v1) seed embedded in the article
"Securing Wealth in Poetry", targeting 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo.

WHY A GPU
---------
Old Electrum v1 turns a seed into a master key by stretching it through
100,000 iterations of SHA256(x || seed).  That is ~44 ms per candidate on a CPU
core (~90 candidates/s on 4 cores), but the iterations of *different candidates*
are completely independent, so a GPU runs thousands of candidates side by side.
Measured search space for the article's GPS/decade model over every carrier,
tokenization and offset is ~2.84 billion candidates:

    CPU  (4 cores, 90 cand/s) ..... ~10,000 h   hopeless
    GPU  (10,000 cand/s) .........  ~79 h      ~3.3 days
    GPU  (30,000 cand/s) .........  ~26 h      ~1 day

SPLIT OF WORK
-------------
  GPU : the 100k-iteration SHA256 stretch (>99% of the cost)
  CPU : candidate generation, and secp256k1 + hash160 + base58 per candidate

ALGORITHM BEING SEARCHED
------------------------
The article documents: "every digit read increases by ten, so 21.493021
translates to: 2, 11, 24, 39, 43, 50, 62, 71", i.e. for the j-th digit of a
landmark's GPS coordinates

    position_j = digit_j + 10*j        (1-indexed word position in the text)

so seed word j must be a wordlist word inside the decade window [10j, 10j+9].
Enumerating all decade-consistent combinations therefore covers EVERY possible
landmark on Earth at once -- no coordinate guessing required.

Verified on the article's own worked example: Supreme Court 38.8906 N,
77.0044 W -> positions 3,18,28,39,40,56,67,77,80,90,104,114, exactly the list
the article prints.

CORRECTNESS
-----------
Run --selftest FIRST.  It checks the GPU kernel against Electrum's own v1 test
vector and cross-checks a batch of GPU stretches against CPU hashlib.  A silent
kernel bug would waste days, so the script refuses to --run until --selftest
has passed on this machine.

REQUIREMENTS
------------
    pip install pyopencl numpy coincurve
(OpenCL works on NVIDIA, AMD and Intel GPUs; NVIDIA ships OpenCL in its driver.
 Intel/AMD CPUs also expose an OpenCL device, useful for testing.)

USAGE
-----
    python electrum_gpu_search.py --selftest
    python electrum_gpu_search.py --bench
    python electrum_gpu_search.py --plan
    python electrum_gpu_search.py --run                       # all work
    python electrum_gpu_search.py --run --shard 0/4           # split over 4 GPUs/PCs
    python electrum_gpu_search.py --run --device 1            # pick an OpenCL device

Progress is checkpointed to progress.json; re-running --run resumes.
A hit is written to FOUND.txt immediately and printed loudly.
"""

import argparse
import hashlib
import itertools
import json
import os
import re
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
SOLVER = os.path.dirname(HERE)
REPO = os.path.dirname(SOLVER)

TARGET = '1K4ezpLybootYF23TM4a8Y4NyP7auysnRo'
ITERS = 100000                     # Electrum v1 stretch rounds
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Electrum v1 test vector (from Electrum's own test suite)
VEC_WORDS = ('powerful random nobody notice nothing important '
             'anyway look away hidden message over').split()
VEC_HEXSEED = 'acb740e454c3134901d7c8f16497cc1c'
VEC_MPK = ('e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df'
           '9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')
VEC_ADDR0 = '1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo'


# --------------------------------------------------------------------------
# Electrum v1 wordlist + mnemonic decoding
# --------------------------------------------------------------------------

def load_wordlist():
    for p in (os.path.join(REPO, 'electrum_words.txt'),
              os.path.join(HERE, 'electrum_words.txt')):
        if os.path.exists(p):
            w = [x.strip() for x in open(p, encoding='utf-8') if x.strip()]
            if len(w) != 1626:
                sys.exit(f'{p}: expected 1626 words, got {len(w)}')
            return w
    sys.exit('electrum_words.txt not found (expected next to the repo root)')

WORDS = load_wordlist()
NW = len(WORDS)
WIDX = {w: i for i, w in enumerate(WORDS)}


def mnemonic_decode(words):
    """Electrum v1: 12 words -> hex seed string. None if not exactly 32 chars.

    A seed Electrum itself generated always decodes to exactly 32 hex chars
    (it encodes a 128-bit value), so requiring that is a correctness filter,
    not just a convenience -- it also keeps every SHA256 message exactly
    64 bytes, which is what the kernel assumes. It drops ~0.38% of arbitrary
    12-word combinations.
    """
    out = []
    for i in range(0, 12, 3):
        try:
            i1 = WIDX[words[i]]
            i2 = WIDX[words[i + 1]] % NW
            i3 = WIDX[words[i + 2]] % NW
        except KeyError:
            return None
        x = i1 + NW * ((i2 - i1) % NW) + NW * NW * ((i3 - i2) % NW)
        if x >= 1 << 32:
            return None
        out.append('%08x' % x)
    return ''.join(out)


# --------------------------------------------------------------------------
# CPU reference stretch (for the self-test)
# --------------------------------------------------------------------------

def stretch_cpu(seed_ascii: bytes) -> bytes:
    x = seed_ascii
    for _ in range(ITERS):
        x = hashlib.sha256(x + seed_ascii).digest()
    return x


# --------------------------------------------------------------------------
# secp256k1 / address side (CPU)
# --------------------------------------------------------------------------

def _import_coincurve():
    try:
        from coincurve import PublicKey
        from coincurve.keys import PrivateKey
        return PublicKey, PrivateKey
    except Exception:
        sys.exit('pip install coincurve')

PublicKey, PrivateKey = _import_coincurve()
_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num = int.from_bytes(payload + chk, 'big')
    out = ''
    while num:
        num, r = divmod(num, 58)
        out = _B58[r] + out
    for b in payload + chk:
        if b:
            break
        out = '1' + out
    return out


def addr_from_pub(pub: bytes) -> str:
    h = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
    return b58check(b'\x00' + h)


def pub_bytes(sec_int: int, compressed: bool) -> bytes:
    return PrivateKey((sec_int % SECP_N).to_bytes(32, 'big')).public_key.format(compressed)


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def electrum_addresses(msec_bytes: bytes, n_addr: int, changes, compressed_too: bool):
    """Yield addresses for one stretched master key (Electrum v1 scheme)."""
    msec = int.from_bytes(msec_bytes, 'big')
    mpk64 = pub_bytes(msec, False)[1:]                 # 64-byte x||y, no 0x04
    for c in changes:
        for n in range(n_addr):
            z = int.from_bytes(sha256d(b'%d:%d:' % (n, c) + mpk64), 'big')
            sec = (msec + z) % SECP_N
            yield (c, n, False, addr_from_pub(pub_bytes(sec, False)))
            if compressed_too:
                yield (c, n, True, addr_from_pub(pub_bytes(sec, True)))


# --------------------------------------------------------------------------
# OpenCL kernel: 100k x SHA256(x || seed), seed and x both 32 bytes
# --------------------------------------------------------------------------

KERNEL_SRC = r'''
#define ROTR(x,n)   (((x) >> (n)) | ((x) << (32u-(n))))
#define CH(x,y,z)   (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z)  (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)      (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x)      (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x)     (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x)     (ROTR(x,17)^ROTR(x,19)^((x)>>10))

__constant uint K[64] = {
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

#define ROUNDS()                                                     \
    for (int i = 16; i < 64; i++)                                     \
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];       \
    a=h0; b=h1; c=h2; d=h3; e=h4; f=h5; g=h6; hh=h7;                  \
    for (int i = 0; i < 64; i++) {                                    \
        t1 = hh + EP1(e) + CH(e,f,g) + K[i] + w[i];                   \
        t2 = EP0(a) + MAJ(a,b,c);                                     \
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;               \
    }                                                                 \
    h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=hh;

/* state: 8 uints per work item, the evolving x (big-endian words)
   seedw: 8 uints per work item, the constant 32-byte ascii hex seed
   Each iteration hashes the 64-byte message x||seed (2 SHA256 compressions;
   the second block is the constant padding for a 64-byte message). */
__kernel void stretch(__global const uint *seedw,
                      __global uint *state,
                      const uint iters)
{
    const size_t gid = get_global_id(0);
    uint s[8], x[8];
    for (int i = 0; i < 8; i++) {
        s[i] = seedw[gid*8 + i];
        x[i] = state[gid*8 + i];
    }
    uint w[64];
    uint h0,h1,h2,h3,h4,h5,h6,h7,a,b,c,d,e,f,g,hh,t1,t2;

    for (uint it = 0; it < iters; it++) {
        h0=0x6a09e667u; h1=0xbb67ae85u; h2=0x3c6ef372u; h3=0xa54ff53au;
        h4=0x510e527fu; h5=0x9b05688cu; h6=0x1f83d9abu; h7=0x5be0cd19u;

        /* block 0: x || seed */
        for (int i = 0; i < 8; i++) w[i]   = x[i];
        for (int i = 0; i < 8; i++) w[8+i] = s[i];
        ROUNDS();

        /* block 1: padding of a 64-byte message */
        w[0] = 0x80000000u;
        for (int i = 1; i < 15; i++) w[i] = 0u;
        w[15] = 512u;
        ROUNDS();

        x[0]=h0; x[1]=h1; x[2]=h2; x[3]=h3; x[4]=h4; x[5]=h5; x[6]=h6; x[7]=h7;
    }
    for (int i = 0; i < 8; i++) state[gid*8 + i] = x[i];
}
'''


class Gpu:
    def __init__(self, device_index=None, chunk_iters=12500):
        try:
            import pyopencl as cl
        except Exception:
            sys.exit('pip install pyopencl')
        self.cl = cl
        devs = []
        for p in cl.get_platforms():
            for d in p.get_devices():
                devs.append(d)
        if not devs:
            sys.exit('no OpenCL devices found')
        if device_index is None:
            gpus = [d for d in devs if d.type & cl.device_type.GPU]
            dev = gpus[0] if gpus else devs[0]
        else:
            dev = devs[device_index]
        self.dev = dev
        self.ctx = cl.Context([dev])
        self.q = cl.CommandQueue(self.ctx)
        self.prg = cl.Program(self.ctx, KERNEL_SRC).build()
        # Retrieve the kernel ONCE: each `prg.stretch` lookup builds a new
        # kernel object, which is expensive and happens per chunked launch.
        self.krn = cl.Kernel(self.prg, 'stretch')
        # chunk_iters keeps a single kernel launch short so a display GPU's
        # watchdog (Windows TDR, ~2 s) does not kill it.
        self.chunk = chunk_iters
        if ITERS % self.chunk:
            sys.exit(f'--chunk-iters must divide {ITERS}')

    def describe(self):
        d = self.dev
        return (f'{d.name.strip()} | {d.platform.name.strip()} | '
                f'CUs={d.max_compute_units} | mem={d.global_mem_size>>20}MiB')

    def list_devices():
        import pyopencl as cl
        out = []
        i = 0
        for p in cl.get_platforms():
            for d in p.get_devices():
                out.append(f'  [{i}] {d.name.strip()}  ({p.name.strip()})')
                i += 1
        return '\n'.join(out)
    list_devices = staticmethod(list_devices)

    def stretch(self, seeds_ascii):
        """seeds_ascii: (n,32) uint8 array of hex-string bytes -> (n,32) uint8 master keys."""
        cl = self.cl
        mf = cl.mem_flags
        n = seeds_ascii.shape[0]
        # bytes -> big-endian uint32 words
        sw = seeds_ascii.reshape(n, 8, 4).astype(np.uint32)
        words = ((sw[:, :, 0] << 24) | (sw[:, :, 1] << 16) |
                 (sw[:, :, 2] << 8) | sw[:, :, 3]).astype(np.uint32)
        state = words.copy()                     # x starts as the seed itself
        g_seed = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=words)
        g_state = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=state)
        done = 0
        while done < ITERS:
            step = min(self.chunk, ITERS - done)
            self.krn(self.q, (n,), None, g_seed, g_state, np.uint32(step))
            done += step
        self.q.finish()
        cl.enqueue_copy(self.q, state, g_state)
        self.q.finish()
        b = state.astype(np.uint32)
        out = np.empty((n, 32), dtype=np.uint8)
        out[:, 0::4] = (b >> 24) & 0xFF
        out[:, 1::4] = (b >> 16) & 0xFF
        out[:, 2::4] = (b >> 8) & 0xFF
        out[:, 3::4] = b & 0xFF
        return out


# --------------------------------------------------------------------------
# Candidate generation: the GPS/decade model over the article
# --------------------------------------------------------------------------

STRIP_RE = re.compile(r"^[^A-Za-z0-9']+|[^A-Za-z0-9']+$")


def tokenize(text, drop_punct_only=True, split_hyphen=False, keep_numbers=True):
    text = (text.replace('‘', "'").replace('’', "'")
                .replace('“', '"').replace('”', '"')
                .replace('–', '-').replace('—', '—'))
    toks = []
    for raw in text.split():
        parts = [p for p in raw.split('-') if p] if (split_hyphen and '-' in raw) else [raw]
        for p in parts:
            c = STRIP_RE.sub('', p)
            if not c:
                if not drop_punct_only:
                    toks.append('')
                continue
            if not keep_numbers and re.fullmatch(r"[0-9']+", c):
                continue
            toks.append(c)
    return [t.lower().strip("'") for t in toks]


def load_blocks():
    p = os.path.join(SOLVER, 'article_blocks.json')
    if not os.path.exists(p):
        sys.exit(f'{p} not found (run solver/extract.py first)')
    return json.load(open(p, encoding='utf-8'))


def build_configs():
    B = load_blocks()

    def txt(idxs):
        return ' '.join(B[i]['text'] for i in idxs)

    body = range(4, 60)
    streams = {
        'all':       txt(range(0, 60)),
        'body':      txt(body),
        'p_only':    txt([i for i in body if B[i]['tag'] in ('p', 'blockquote')]),
        'noheads':   txt([i for i in body if B[i]['tag'] not in ('h1', 'h2', 'h3')]),
        'nocap':     txt([i for i in body if B[i]['tag'] != 'figcaption']),
        'p_pre':     txt([i for i in body if B[i]['tag'] in ('p', 'blockquote', 'pre')]),
        'rev':       txt(range(4, 14)),
        'rev_nocap': txt([i for i in range(4, 14) if B[i]['tag'] != 'figcaption']),
        'rev_h':     txt(range(3, 14)),
    }
    for i in body:
        if B[i]['tag'] in ('p', 'pre', 'blockquote', 'figcaption'):
            streams['para_%d' % i] = B[i]['text']

    cfgs = []
    for name, text in streams.items():
        for dp in (True, False):
            for sh in (False, True):
                for kn in (True, False):
                    toks = tokenize(text, dp, sh, kn)
                    if len(toks) < 111:
                        continue
                    cfgs.append({
                        'label': f'{name}|dp{int(dp)}sh{int(sh)}kn{int(kn)}',
                        'toks': toks,
                        'inlist': [t in WIDX for t in toks],
                    })
    return cfgs


def offset_options(cfg, off):
    """Per-decade candidate words, or None if some decade window is empty."""
    toks, inl, n = cfg['toks'], cfg['inlist'], len(cfg['toks'])
    opts = []
    for j in range(12):
        base = off + 10 * j
        o = [toks[base + d - 1] for d in range(10)
             if 1 <= base + d <= n and inl[base + d - 1]]
        if not o:
            return None
        opts.append(o)
    return opts


def work_units(cfgs):
    """Every (config, offset) that is structurally feasible, with its size."""
    units = []
    for ci, cfg in enumerate(cfgs):
        hi = len(cfg['toks']) - 110
        for off in range(0, max(1, hi + 1)):
            opts = offset_options(cfg, off)
            if opts is None:
                continue
            tot = 1
            for o in opts:
                tot *= len(o)
            units.append((ci, off, tot))
    return units


def iter_candidates(cfg, off):
    opts = offset_options(cfg, off)
    if opts is None:
        return
    for combo in itertools.product(*opts):
        yield combo


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------

def do_selftest(args):
    print('== CPU reference ==')
    hs = mnemonic_decode(VEC_WORDS)
    assert hs == VEC_HEXSEED, (hs, VEC_HEXSEED)
    print(f'  mnemonic_decode OK  ({hs})')
    t0 = time.time()
    msec = stretch_cpu(hs.encode())
    print(f'  stretch_cpu OK      ({time.time()-t0:.2f}s)')
    mpk = pub_bytes(int.from_bytes(msec, 'big'), False)[1:]
    assert mpk.hex() == VEC_MPK, mpk.hex()
    print('  master public key   OK')
    got = [a for (c, n, comp, a) in electrum_addresses(msec, 1, (0,), False)]
    assert got[0] == VEC_ADDR0, got
    print(f'  address 0           OK  ({got[0]})')

    print('== GPU ==')
    gpu = Gpu(args.device, args.chunk_iters)
    print('  device:', gpu.describe())
    seeds = np.frombuffer(hs.encode(), dtype=np.uint8).reshape(1, 32)
    out = gpu.stretch(seeds)
    g = bytes(out[0])
    print(f'  GPU stretch         {"OK" if g == msec else "MISMATCH"}')
    if g != msec:
        print(f'    cpu={msec.hex()}\n    gpu={g.hex()}')
        sys.exit('GPU KERNEL IS WRONG -- do not run the search')
    gmpk = pub_bytes(int.from_bytes(g, 'big'), False)[1:]
    assert gmpk.hex() == VEC_MPK
    a = [x for (c, n, comp, x) in electrum_addresses(g, 1, (0,), False)][0]
    assert a == VEC_ADDR0
    print(f'  GPU -> address 0    OK  ({a})')

    print('== GPU vs CPU on a random batch ==')
    rs = np.random.RandomState(1234)
    batch = []
    for _ in range(8):
        v = rs.randint(0, 1 << 32, size=4, dtype=np.uint64)
        batch.append(''.join('%08x' % int(x) for x in v))
    arr = np.frombuffer(''.join(batch).encode(), dtype=np.uint8).reshape(len(batch), 32)
    gout = gpu.stretch(arr)
    bad = 0
    for i, s in enumerate(batch):
        if bytes(gout[i]) != stretch_cpu(s.encode()):
            bad += 1
            print(f'  MISMATCH on {s}')
    if bad:
        sys.exit(f'{bad}/{len(batch)} mismatched -- GPU KERNEL IS WRONG')
    print(f'  {len(batch)}/{len(batch)} match')

    open(os.path.join(HERE, '.selftest_ok'), 'w').write(gpu.describe() + '\n')
    print('\nSELFTEST PASSED -- --run is now unlocked on this machine.')


def do_bench(args):
    gpu = Gpu(args.device, args.chunk_iters)
    print('device:', gpu.describe())
    sizes = sorted({max(64, args.batch // 16), max(128, args.batch // 4), args.batch})
    for n in sizes:
        if n <= 0:
            continue
        rs = np.random.RandomState(7)
        hexs = ''.join('%08x' % int(x) for x in rs.randint(0, 1 << 32, size=4 * n, dtype=np.uint64))
        arr = np.frombuffer(hexs.encode(), dtype=np.uint8).reshape(n, 32)
        t0 = time.time()
        gpu.stretch(arr)
        dt = time.time() - t0
        print(f'  batch {n:>7}: {dt:6.2f}s -> {n/dt:9.0f} stretch/s '
              f'({n/dt*ITERS*2/1e9:.2f} GH/s SHA256)')
    print('\nThe EC/address stage runs on the CPU; measuring it:')
    msec = stretch_cpu(VEC_HEXSEED.encode())
    t0 = time.time()
    k = 300
    for _ in range(k):
        list(electrum_addresses(msec, args.addrs, tuple(range(args.changes)), args.compressed))
    dt = time.time() - t0
    per = dt / k
    print(f'  {args.addrs} addr x {args.changes} change: {per*1000:.2f} ms/candidate'
          f' -> {1/per:.0f}/s per core, ~{args.procs/per:.0f}/s on {args.procs} procs')
    print('\nIf the CPU figure is below the GPU figure, lower --addrs/--changes'
          ' or raise --procs.')


def _ec_worker(chunk):
    """chunk: list of (mnemonic_str, master_key_bytes). Returns hits."""
    n_addr, changes, comp = _EC_CFG
    hits = []
    for mn, msec in chunk:
        for (c, n, cm, a) in electrum_addresses(msec, n_addr, changes, comp):
            if a == TARGET:
                hits.append((mn, c, n, cm, a))
    return hits


_EC_CFG = (3, (0, 1), False)


def _init_ec(cfg):
    global _EC_CFG
    _EC_CFG = cfg


def do_plan(args):
    cfgs = build_configs()
    units = work_units(cfgs)
    units.sort(key=lambda u: (u[2], u[0], u[1]))
    tot = sum(u[2] for u in units)
    print(f'configs            : {len(cfgs)}')
    print(f'feasible work units: {len(units):,}')
    print(f'total candidates   : {tot:,}')
    for rate in (5000, 10000, 20000, 40000):
        print(f'  at {rate:>6,}/s : {tot/rate/3600:8.1f} h  ({tot/rate/86400:.1f} days)')
    cum = 0
    print('\ncheapest units first (the search order used by --run):')
    for i, (ci, off, t) in enumerate(units[:10]):
        cum += t
        print(f'  {cfgs[ci]["label"]:34} off={off:<5} {t:>12,}')
    print('  ...')
    big = units[-5:]
    for (ci, off, t) in big:
        print(f'  {cfgs[ci]["label"]:34} off={off:<5} {t:>12,}  (largest)')


def do_run(args):
    if not os.path.exists(os.path.join(HERE, '.selftest_ok')):
        sys.exit('run --selftest first (it validates the GPU kernel on this machine)')
    from multiprocessing import Pool

    cfgs = build_configs()
    units = work_units(cfgs)
    # cheapest first: maximises the chance of an early hit per unit of time
    units.sort(key=lambda u: (u[2], u[0], u[1]))
    if args.shard:
        i, k = (int(x) for x in args.shard.split('/'))
        units = [u for idx, u in enumerate(units) if idx % k == i]
        print(f'shard {i}/{k}: {len(units):,} work units')

    ck_path = os.path.join(HERE, args.checkpoint)
    done = set()
    if os.path.exists(ck_path):
        try:
            done = set(tuple(x) for x in json.load(open(ck_path))['done'])
            print(f'resuming: {len(done):,} work units already done')
        except Exception:
            print('checkpoint unreadable, starting fresh')

    gpu = Gpu(args.device, args.chunk_iters)
    print('device:', gpu.describe())
    total = sum(t for (ci, off, t) in units if (ci, off) not in done)
    print(f'candidates to check: {total:,}')

    ec_cfg = (args.addrs, tuple(range(args.changes)), args.compressed)
    pool = Pool(args.procs, initializer=_init_ec, initargs=(ec_cfg,))

    t_start = time.time()
    checked = 0
    pend_mn, pend_seed = [], []
    ready = []            # units fully enqueued, awaiting the next flush
    hits_all = []
    last_ck = [time.time()]

    def save_ck():
        tmp = ck_path + '.tmp'
        json.dump({'done': sorted(done)}, open(tmp, 'w'))
        os.replace(tmp, ck_path)       # atomic: a kill mid-write cannot corrupt it
        last_ck[0] = time.time()

    def flush():
        """Dispatch the pending buffer, then retire every fully-enqueued unit.

        Units are only marked done after a flush that has processed all of
        their candidates, so an interrupt can never skip unchecked work.
        """
        nonlocal checked, pend_mn, pend_seed, ready
        if pend_mn:
            arr = np.frombuffer(''.join(pend_seed).encode(), dtype=np.uint8)
            arr = arr.reshape(len(pend_seed), 32)
            keys = gpu.stretch(arr)
            pairs = [(pend_mn[i], bytes(keys[i])) for i in range(len(pend_mn))]
            csz = max(1, len(pairs) // (args.procs * 4))
            chunks = [pairs[i:i + csz] for i in range(0, len(pairs), csz)]
            for res in pool.imap_unordered(_ec_worker, chunks):
                for h in res:
                    hits_all.append(h)
                    msg = ('\n' + '!' * 70 +
                           f'\n*** FOUND ***\nmnemonic : {h[0]}\n'
                           f'change={h[1]} index={h[2]} compressed={h[3]}\n'
                           f'address  : {h[4]}\n' + '!' * 70 + '\n')
                    print(msg, flush=True)
                    with open(os.path.join(HERE, 'FOUND.txt'), 'a') as f:
                        f.write(msg)
            checked += len(pend_mn)
            pend_mn, pend_seed = [], []
            el = time.time() - t_start
            rate = checked / el if el else 0
            eta = (total - checked) / rate / 3600 if rate else 0
            print(f'  {checked:,}/{total:,} ({100*checked/max(total,1):.3f}%) '
                  f'{rate:,.0f}/s eta {eta:,.1f} h  hits={len(hits_all)}', flush=True)
        if ready:
            done.update(ready)
            ready = []
        # checkpoint on a timer, not per unit: rewriting the whole file for each
        # of 26k units would be quadratic
        if time.time() - last_ck[0] > args.checkpoint_secs:
            save_ck()

    try:
        for (ci, off, t) in units:
            if (ci, off) in done:
                continue
            cfg = cfgs[ci]
            for combo in iter_candidates(cfg, off):
                hs = mnemonic_decode(combo)
                if hs is None:
                    continue
                pend_mn.append(' '.join(combo))
                pend_seed.append(hs)
                # Do NOT flush per work unit: units can be as small as 15
                # candidates, and an under-filled dispatch leaves the GPU idle.
                if len(pend_mn) >= args.batch:
                    flush()
            ready.append((ci, off))
        flush()
        save_ck()
    except KeyboardInterrupt:
        print('\ninterrupted; flushing and checkpointing')
        flush()
        save_ck()
    finally:
        pool.close()
        pool.join()

    el = time.time() - t_start
    print(f'\nDONE checked={checked:,} in {el/3600:.2f} h  hits={len(hits_all)}')
    if not hits_all:
        print('no match in the covered space')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--selftest', action='store_true', help='validate the GPU kernel (do this first)')
    ap.add_argument('--bench', action='store_true', help='measure GPU and CPU throughput')
    ap.add_argument('--plan', action='store_true', help='print the search space and ETA')
    ap.add_argument('--run', action='store_true', help='run the search')
    ap.add_argument('--list-devices', action='store_true')
    ap.add_argument('--device', type=int, default=None, help='OpenCL device index')
    ap.add_argument('--batch', type=int, default=16384, help='candidates per GPU dispatch')
    ap.add_argument('--chunk-iters', type=int, default=12500,
                    help='stretch iterations per kernel launch (must divide 100000); '
                         'lower it if a display-GPU watchdog kills the kernel')
    ap.add_argument('--procs', type=int, default=max(1, (os.cpu_count() or 4) - 1),
                    help='CPU processes for the secp256k1/address stage')
    ap.add_argument('--addrs', type=int, default=3, help='address indices per change branch')
    ap.add_argument('--changes', type=int, default=2, help='1 = receiving only, 2 = + change')
    ap.add_argument('--compressed', action='store_true',
                    help='also test compressed keys (Electrum v1 used uncompressed)')
    ap.add_argument('--shard', default=None, help='i/N -- split work across GPUs or machines')
    ap.add_argument('--checkpoint', default='progress.json')
    ap.add_argument('--checkpoint-secs', type=float, default=60.0,
                    help='how often to rewrite the checkpoint file')
    args = ap.parse_args()

    if args.list_devices:
        print(Gpu.list_devices()); return
    if args.selftest:
        do_selftest(args); return
    if args.bench:
        do_bench(args); return
    if args.plan:
        do_plan(args); return
    if args.run:
        do_run(args); return
    ap.print_help()


if __name__ == '__main__':
    main()
