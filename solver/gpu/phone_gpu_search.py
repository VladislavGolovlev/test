#!/usr/bin/env python3
"""
GPU search for the PHONE-METHOD seed hidden in "Securing Wealth in Poetry",
targeting 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo.

THE HYPOTHESIS
--------------
The article's "Story & phone number" method scatters BIP39 seed words through a
purpose-written story and keeps the positional key OFF the page:

    "Two or three phone numbers are then written after the story is
     constructed... These should be written on a different page to remove any
     connection between the text and the numbers."

So the key is deliberately unrecoverable from the article and brute-forcing the
positions is the intended path. The closing hint matches exactly: it promises
every **word**, never the numbers.

The carrier is one of the two worked examples, because they are the only
purpose-written, seed-dense texts in the article:

    phone example      125 tokens   51 BIP39 words   41%
    GPS example        125 tokens   36 BIP39 words   29%
    Revolution story   596 tokens  112 BIP39 words   19%   (natural prose)

The phone example is the prime suspect: it is the densest, the method states it
holds "true and decoy seed phrases", and its own published numbers decode to an
INVALID phrase (`a` at position 113 is not a BIP39 word), marking the published
reading as a decoy.

The author's own tooling is BIP39: the GPS example, which he wrote himself,
decodes to a 12-word BIP39 mnemonic with a VALID checksum (1-in-16 by chance).

SEARCH SPACE AND THE PRUNE
--------------------------
Positions are a greedy ascending read of the concatenated phone digits, so the
12 positions' TOTAL DIGIT COUNT equals the digits of 2-3 phone numbers.
Verified on the published example: 2,6,9,18,22,25,45,70,86,100,113,116 has
digit-lengths 1,1,1,2,2,2,2,2,2,3,3,3 = 24 = two 12-digit numbers.

    carrier        slice                      combos       checksum-valid
    GPS example    3 phones (30-39 digits)     9,238,671          577,417
    GPS example    24 digits                 214,526,520       13,407,908
    GPS example    2 phones (20-26 digits) 1,208,613,315       75,538,332
    phone example  3 phones (30-39 digits)   958,995,275       59,937,205
    phone example  24 digits (published)  26,640,902,470    1,665,056,404
    phone example  2 phones (20-26)     117,873,413,580    7,367,088,349

WHY THE WORK IS SPLIT THE WAY IT IS
-----------------------------------
Enumerating 26.6 billion 12-subsets in Python is hopeless (~5 us each is 37
CPU-days), so BOTH the enumeration and the expensive KDF run on the GPU:

  GPU kernel 1  combinatorial unranking -> 12 word indices -> BIP39 checksum
                test. Only 1/16 survive, and they are compacted with an atomic
                counter, so the host never touches the other 15/16.
  GPU kernel 2  PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048) for survivors.
                The HMAC key schedule is hoisted out of the 2048-iteration
                loop, so each iteration costs exactly 2 SHA512 compressions.
  CPU           BIP32 m/44'/0'/0'/0/0 + secp256k1 + hash160 for survivors only.

The CPU stage is usually the limiter: m/44'/0'/0'/0/0 needs 3 EC multiplies
(~180 us), i.e. ~5.5k/s per core. On a 16-core desktop that is ~88k/s, so the
1.67-billion "24 digits" slice is roughly 5-6 hours; `--bench` tells you your
real numbers. Use `--shard i/N` to spread it over machines.

REQUIREMENTS
------------
    pip install pyopencl numpy coincurve

USAGE
-----
    python phone_gpu_search.py --selftest      # validate kernels; required
    python phone_gpu_search.py --list
    python phone_gpu_search.py --bench
    python phone_gpu_search.py --run --slice 4
    python phone_gpu_search.py --run --slice 4 --shard 0/4
"""
import argparse
import hashlib
import itertools
import json
import math
import os
import sys
import time
from multiprocessing import Pool

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
SOLVER = os.path.dirname(HERE)
REPO = os.path.dirname(SOLVER)
sys.path.insert(0, SOLVER)
import btclib as B          # noqa: E402  (verified against the BIP39 test vector)
import tok as T             # noqa: E402

TARGET = '1K4ezpLybootYF23TM4a8Y4NyP7auysnRo'
WL = B.load_wordlist(os.path.join(REPO, 'word.txt'))
IDX = {w: i for i, w in enumerate(WL)}
WSET = set(WL)
BLOCKS = json.load(open(os.path.join(SOLVER, 'article_blocks.json'), encoding='utf-8'))
PATH = "m/44'/0'/0'/0/0"


# ----------------------------------------------------------------------------
# carrier / slices  (kept identical to the CPU reference solver)
# ----------------------------------------------------------------------------

def carrier(block_idx):
    body = BLOCKS[block_idx]['text'].split('Example:', 1)[-1].split('-------------')[0]
    return [t.lower().strip("'") for t in T.tokenize(body)]


def groups(low):
    g = {1: [], 2: [], 3: []}
    for i, w in enumerate(low):
        if w in WSET:
            p = i + 1
            g[len(str(p))].append(p)
    return g


def profiles(g, totals):
    out = []
    for a in range(0, min(len(g[1]), 12) + 1):
        for b in range(0, min(len(g[2]), 12 - a) + 1):
            c = 12 - a - b
            if c < 0 or c > len(g[3]):
                continue
            if a + 2 * b + 3 * c in totals:
                out.append((a, b, c))
    return out


SLICES = [
    ('GPS example',   53, tuple(range(30, 40)), '3 phones (30-39 digits)'),
    ('GPS example',   53, (24,),                '24 digits'),
    ('GPS example',   53, tuple(range(20, 27)), '2 phones (20-26 digits)'),
    ('phone example', 51, tuple(range(30, 40)), '3 phones (30-39 digits)'),
    ('phone example', 51, (24,),                '24 digits (as published)'),
    ('phone example', 51, tuple(range(20, 27)), '2 phones (20-26 digits)'),
]


def unrank(n, k, r, out):
    """Lexicographic unranking of the r-th k-subset of range(n). Reference impl."""
    x = 0
    for i in range(k):
        for v in range(x, n):
            c = math.comb(n - v - 1, k - i - 1)
            if r < c:
                out[i] = v
                x = v + 1
                break
            r -= c
    return out


# ----------------------------------------------------------------------------
# OpenCL kernels
# ----------------------------------------------------------------------------

KERNEL_SRC = r'''
/* ============================ SHA-256 ============================ */
#define R32(x,n)  (((x) >> (n)) | ((x) << (32u-(n))))
#define CH(x,y,z)  (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define E0(x) (R32(x,2)^R32(x,13)^R32(x,22))
#define E1(x) (R32(x,6)^R32(x,11)^R32(x,25))
#define S0(x) (R32(x,7)^R32(x,18)^((x)>>3))
#define S1(x) (R32(x,17)^R32(x,19)^((x)>>10))

__constant uint K256[64] = {
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

/* SHA-256 of a 16-byte message (the BIP39 entropy). One block. */
inline uint sha256_16_first_byte(const uchar *m)
{
    uint w[64];
    uint h0=0x6a09e667u,h1=0xbb67ae85u,h2=0x3c6ef372u,h3=0xa54ff53au,
         h4=0x510e527fu,h5=0x9b05688cu,h6=0x1f83d9abu,h7=0x5be0cd19u;
    for (int i=0;i<4;i++)
        w[i] = ((uint)m[4*i]<<24)|((uint)m[4*i+1]<<16)|((uint)m[4*i+2]<<8)|(uint)m[4*i+3];
    w[4]=0x80000000u;
    for (int i=5;i<15;i++) w[i]=0u;
    w[15]=128u;                        /* 16 bytes = 128 bits */
    for (int i=16;i<64;i++) w[i]=S1(w[i-2])+w[i-7]+S0(w[i-15])+w[i-16];
    uint a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7,t1,t2;
    for (int i=0;i<64;i++){
        t1=hh+E1(e)+CH(e,f,g)+K256[i]+w[i];
        t2=E0(a)+MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    return (h0+a) >> 24;               /* first byte of the digest */
}

/* ============================ SHA-512 ============================ */
#define R64(x,n) (((x) >> (n)) | ((x) << (64ul-(n))))
#define BE0(x) (R64(x,28)^R64(x,34)^R64(x,39))
#define BE1(x) (R64(x,14)^R64(x,18)^R64(x,41))
#define BS0(x) (R64(x,1)^R64(x,8)^((x)>>7))
#define BS1(x) (R64(x,19)^R64(x,61)^((x)>>6))

__constant ulong K512[80] = {
0x428a2f98d728ae22ul,0x7137449123ef65cdul,0xb5c0fbcfec4d3b2ful,0xe9b5dba58189dbbcul,
0x3956c25bf348b538ul,0x59f111f1b605d019ul,0x923f82a4af194f9bul,0xab1c5ed5da6d8118ul,
0xd807aa98a3030242ul,0x12835b0145706fbeul,0x243185be4ee4b28cul,0x550c7dc3d5ffb4e2ul,
0x72be5d74f27b896ful,0x80deb1fe3b1696b1ul,0x9bdc06a725c71235ul,0xc19bf174cf692694ul,
0xe49b69c19ef14ad2ul,0xefbe4786384f25e3ul,0x0fc19dc68b8cd5b5ul,0x240ca1cc77ac9c65ul,
0x2de92c6f592b0275ul,0x4a7484aa6ea6e483ul,0x5cb0a9dcbd41fbd4ul,0x76f988da831153b5ul,
0x983e5152ee66dfabul,0xa831c66d2db43210ul,0xb00327c898fb213ful,0xbf597fc7beef0ee4ul,
0xc6e00bf33da88fc2ul,0xd5a79147930aa725ul,0x06ca6351e003826ful,0x142929670a0e6e70ul,
0x27b70a8546d22ffcul,0x2e1b21385c26c926ul,0x4d2c6dfc5ac42aedul,0x53380d139d95b3dful,
0x650a73548baf63deul,0x766a0abb3c77b2a8ul,0x81c2c92e47edaee6ul,0x92722c851482353bul,
0xa2bfe8a14cf10364ul,0xa81a664bbc423001ul,0xc24b8b70d0f89791ul,0xc76c51a30654be30ul,
0xd192e819d6ef5218ul,0xd69906245565a910ul,0xf40e35855771202aul,0x106aa07032bbd1b8ul,
0x19a4c116b8d2d0c8ul,0x1e376c085141ab53ul,0x2748774cdf8eeb99ul,0x34b0bcb5e19b48a8ul,
0x391c0cb3c5c95a63ul,0x4ed8aa4ae3418acbul,0x5b9cca4f7763e373ul,0x682e6ff3d6b2b8a3ul,
0x748f82ee5defb2fcul,0x78a5636f43172f60ul,0x84c87814a1f0ab72ul,0x8cc702081a6439ecul,
0x90befffa23631e28ul,0xa4506cebde82bde9ul,0xbef9a3f7b2c67915ul,0xc67178f2e372532bul,
0xca273eceea26619cul,0xd186b8c721c0c207ul,0xeada7dd6cde0eb1eul,0xf57d4f7fee6ed178ul,
0x06f067aa72176fbaul,0x0a637dc5a2c898a6ul,0x113f9804bef90daeul,0x1b710b35131c471bul,
0x28db77f523047d84ul,0x32caab7b40c72493ul,0x3c9ebe0a15c9bebcul,0x431d67c49c100d4cul,
0x4cc5d4becb3e42b6ul,0x597f299cfc657e2aul,0x5fcb6fab3ad6faecul,0x6c44198c4a475817ul};

/* One SHA-512 compression: state h[8] absorbs the 128-byte block w[16]. */
inline void sha512_compress(ulong *h, const ulong *win)
{
    ulong w[80];
    for (int i=0;i<16;i++) w[i]=win[i];
    for (int i=16;i<80;i++) w[i]=BS1(w[i-2])+w[i-7]+BS0(w[i-15])+w[i-16];
    ulong a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7],t1,t2;
    for (int i=0;i<80;i++){
        t1=hh+BE1(e)+CH(e,f,g)+K512[i]+w[i];
        t2=BE0(a)+MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

__constant ulong IV512[8] = {
0x6a09e667f3bcc908ul,0xbb67ae8584caa73bul,0x3c6ef372fe94f82bul,0xa54ff53a5f1d36f1ul,
0x510e527fade682d1ul,0x9b05688c2b3e6c1ful,0x1f83d9abfb41bd6bul,0x5be0cd19137e2179ul};

/* PBKDF2-HMAC-SHA512(pw, "mnemonic" || 00000001, 2048), dkLen = 64.
   The ipad/opad states depend only on the password, so they are computed once
   and reused for all 2048 iterations: each iteration is then exactly two
   SHA-512 compressions. */
inline void pbkdf2(const uchar *pw, uint pwlen, uchar *out)
{
    ulong ib[16], ob[16];
    for (int i=0;i<16;i++){ ib[i]=0ul; ob[i]=0ul; }
    /* K' (zero padded to 128 bytes) xor ipad/opad, as big-endian ulongs */
    for (uint i=0;i<pwlen;i++){
        ib[i>>3] |= ((ulong)pw[i]) << (56 - 8*(i&7));
        ob[i>>3] |= ((ulong)pw[i]) << (56 - 8*(i&7));
    }
    for (int i=0;i<16;i++){ ib[i]^=0x3636363636363636ul; ob[i]^=0x5c5c5c5c5c5c5c5cul; }
    ulong istate[8], ostate[8];
    for (int i=0;i<8;i++){ istate[i]=IV512[i]; ostate[i]=IV512[i]; }
    sha512_compress(istate, ib);
    sha512_compress(ostate, ob);

    /* U1 = HMAC(pw, salt || INT32BE(1));  salt = "mnemonic" (8 bytes) */
    ulong blk[16];
    for (int i=0;i<16;i++) blk[i]=0ul;
    blk[0]=0x6d6e656d6f6e6963ul;                 /* "mnemonic" */
    blk[1]=0x0000000180000000ul;                 /* 00000001 || 0x80 pad */
    blk[15]=(ulong)((128+12)*8);
    ulong h[8];
    for (int i=0;i<8;i++) h[i]=istate[i];
    sha512_compress(h, blk);
    /* outer */
    ulong ub[16];
    for (int i=0;i<8;i++) ub[i]=h[i];
    ub[8]=0x8000000000000000ul;
    for (int i=9;i<15;i++) ub[i]=0ul;
    ub[15]=(ulong)((128+64)*8);
    for (int i=0;i<8;i++) h[i]=ostate[i];
    sha512_compress(h, ub);

    ulong dk[8], u[8];
    for (int i=0;i<8;i++){ dk[i]=h[i]; u[i]=h[i]; }

    for (int it=1; it<2048; it++){
        /* inner: H(istate, u || pad) */
        for (int i=0;i<8;i++) ub[i]=u[i];
        ub[8]=0x8000000000000000ul;
        for (int i=9;i<15;i++) ub[i]=0ul;
        ub[15]=(ulong)((128+64)*8);
        for (int i=0;i<8;i++) h[i]=istate[i];
        sha512_compress(h, ub);
        /* outer: H(ostate, inner || pad) */
        for (int i=0;i<8;i++) ub[i]=h[i];
        ub[8]=0x8000000000000000ul;
        for (int i=9;i<15;i++) ub[i]=0ul;
        ub[15]=(ulong)((128+64)*8);
        for (int i=0;i<8;i++) h[i]=ostate[i];
        sha512_compress(h, ub);
        for (int i=0;i<8;i++){ u[i]=h[i]; dk[i]^=h[i]; }
    }
    for (int i=0;i<8;i++)
        for (int j=0;j<8;j++)
            out[8*i+j] = (uchar)(dk[i] >> (56-8*j));
}

/* ---- kernel 1: unrank a combination, test the BIP39 checksum, compact ---- */
inline void unrank_k(uint n, uint k, ulong r, __global const ulong *binom,
                     uint *out)
{
    uint x = 0;
    for (uint i=0;i<k;i++){
        for (uint v=x; v<n; v++){
            ulong c = binom[(n-v-1)*13 + (k-i-1)];
            if (r < c){ out[i]=v; x=v+1; break; }
            r -= c;
        }
    }
}

__kernel void enumerate(__global const ulong *binom,
                        __global const ushort *widx1,   /* BIP39 index per group-1 position */
                        __global const ushort *widx2,
                        __global const ushort *widx3,
                        const uint n1, const uint n2, const uint n3,
                        const uint a, const uint b, const uint c,
                        const ulong rank0, const ulong count,
                        const ulong cb, const ulong cc,
                        __global ushort *out_words,     /* 12 per survivor */
                        __global ulong *out_rank,       /* global rank per survivor */
                        volatile __global uint *counter,
                        const uint out_cap)
{
    ulong gid = (ulong)get_global_id(0);
    if (gid >= count) return;
    ulong r = rank0 + gid;
    ulong ra = r / (cb*cc);
    ulong rem = r % (cb*cc);
    ulong rb = rem / cc;
    ulong rc = rem % cc;

    uint ia[12], ib2[12], ic[12];
    if (a) unrank_k(n1, a, ra, binom, ia);
    if (b) unrank_k(n2, b, rb, binom, ib2);
    if (c) unrank_k(n3, c, rc, binom, ic);

    ushort wi[12];
    uint t=0;
    for (uint i=0;i<a;i++) wi[t++] = widx1[ia[i]];
    for (uint i=0;i<b;i++) wi[t++] = widx2[ib2[i]];
    for (uint i=0;i<c;i++) wi[t++] = widx3[ic[i]];

    /* pack 12 x 11 bits = 132 bits; entropy = top 128, checksum = low 4 */
    uchar ent[16];
    for (int i=0;i<16;i++) ent[i]=0;
    /* bit j of the 132-bit string */
    for (uint i=0;i<12;i++){
        uint v = wi[i];
        for (int bit=10; bit>=0; bit--){
            uint pos = i*11 + (10-bit);
            if (pos >= 128) break;
            if ((v >> bit) & 1u) ent[pos>>3] |= (uchar)(0x80u >> (pos&7));
        }
    }
    /* the 4 checksum bits are the last 4 bits of the 132-bit string,
       i.e. the low 4 bits of word 11 */
    uint cks = wi[11] & 0xFu;
    uint first = sha256_16_first_byte(ent);
    if ((first >> 4) != cks) return;

    uint slot = atomic_inc(counter);
    if (slot >= out_cap) return;
    for (uint i=0;i<12;i++) out_words[slot*12+i] = wi[i];
    out_rank[slot] = r;
}

/* ---- kernel 2: PBKDF2 over survivors, building the mnemonic on-device ---- */
__kernel void seeds(__global const ushort *words,       /* 12 per candidate */
                    __global const uchar *wlbytes,      /* packed wordlist */
                    __global const uint *wloff,         /* 2049 offsets */
                    __global uchar *out,                /* 64 bytes per cand */
                    const uint count)
{
    uint gid = get_global_id(0);
    if (gid >= count) return;
    uchar pw[128];
    uint L = 0;
    for (uint i=0;i<12;i++){
        if (i) pw[L++] = ' ';
        uint w = words[gid*12+i];
        uint s = wloff[w], e = wloff[w+1];
        for (uint j=s;j<e;j++) pw[L++] = wlbytes[j];
    }
    uchar dk[64];
    pbkdf2(pw, L, dk);
    for (int i=0;i<64;i++) out[gid*64+i] = dk[i];
}
'''


class Gpu:
    def __init__(self, device_index=None):
        try:
            import pyopencl as cl
        except Exception:
            sys.exit('pip install pyopencl')
        self.cl = cl
        devs = [d for p in cl.get_platforms() for d in p.get_devices()]
        if not devs:
            sys.exit('no OpenCL devices found')
        if device_index is None:
            g = [d for d in devs if d.type & cl.device_type.GPU]
            dev = g[0] if g else devs[0]
        else:
            dev = devs[device_index]
        self.dev = dev
        self.ctx = cl.Context([dev])
        self.q = cl.CommandQueue(self.ctx)
        self.prg = cl.Program(self.ctx, KERNEL_SRC).build()
        self.k_enum = cl.Kernel(self.prg, 'enumerate')
        self.k_seed = cl.Kernel(self.prg, 'seeds')
        mf = cl.mem_flags
        # binomial table C(n, k) for n<=51, k<=12
        bn = np.zeros((52, 13), dtype=np.uint64)
        for n in range(52):
            for k in range(13):
                bn[n, k] = math.comb(n, k) if k <= n else 0
        self.g_binom = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
                                 hostbuf=bn.reshape(-1))
        packed = b''.join(w.encode() for w in WL)
        offs = np.zeros(len(WL) + 1, dtype=np.uint32)
        acc = 0
        for i, w in enumerate(WL):
            offs[i] = acc
            acc += len(w)
        offs[len(WL)] = acc
        self.g_wl = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
                              hostbuf=np.frombuffer(packed, dtype=np.uint8))
        self.g_off = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=offs)

    def describe(self):
        d = self.dev
        return (f'{d.name.strip()} | {d.platform.name.strip()} | '
                f'CUs={d.max_compute_units} | mem={d.global_mem_size>>20}MiB')

    @staticmethod
    def list_devices():
        import pyopencl as cl
        out, i = [], 0
        for p in cl.get_platforms():
            for d in p.get_devices():
                out.append(f'  [{i}] {d.name.strip()}  ({p.name.strip()})')
                i += 1
        return '\n'.join(out)

    def enumerate_batch(self, gi, prof, rank0, count, cap):
        """Run kernel 1; return (word_index_array, ranks, n_survivors)."""
        cl = self.cl
        mf = cl.mem_flags
        a, b, c = prof
        n1, n2, n3 = gi['n']
        cb = math.comb(n2, b) if b else 1
        cc = math.comb(n3, c) if c else 1
        words = np.zeros(cap * 12, dtype=np.uint16)
        ranks = np.zeros(cap, dtype=np.uint64)
        cnt = np.zeros(1, dtype=np.uint32)
        g_w = cl.Buffer(self.ctx, mf.WRITE_ONLY, words.nbytes)
        g_r = cl.Buffer(self.ctx, mf.WRITE_ONLY, ranks.nbytes)
        g_c = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=cnt)
        self.k_enum(self.q, (int(count),), None,
                    self.g_binom, gi['g1'], gi['g2'], gi['g3'],
                    np.uint32(n1), np.uint32(n2), np.uint32(n3),
                    np.uint32(a), np.uint32(b), np.uint32(c),
                    np.uint64(rank0), np.uint64(count),
                    np.uint64(cb), np.uint64(cc),
                    g_w, g_r, g_c, np.uint32(cap))
        cl.enqueue_copy(self.q, cnt, g_c)
        self.q.finish()
        ns = int(min(cnt[0], cap))
        if ns:
            cl.enqueue_copy(self.q, words, g_w)
            cl.enqueue_copy(self.q, ranks, g_r)
            self.q.finish()
        return words[:ns * 12].reshape(-1, 12), ranks[:ns], int(cnt[0])

    def seeds_batch(self, widx):
        cl = self.cl
        mf = cl.mem_flags
        n = widx.shape[0]
        flat = np.ascontiguousarray(widx.reshape(-1), dtype=np.uint16)
        out = np.zeros(n * 64, dtype=np.uint8)
        g_in = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=flat)
        g_out = cl.Buffer(self.ctx, mf.WRITE_ONLY, out.nbytes)
        self.k_seed(self.q, (n,), None, g_in, self.g_wl, self.g_off,
                    g_out, np.uint32(n))
        cl.enqueue_copy(self.q, out, g_out)
        self.q.finish()
        return out.reshape(n, 64)

    def group_buffers(self, g, low):
        cl = self.cl
        mf = cl.mem_flags
        arrs = {}
        for key, gnum in (('g1', 1), ('g2', 2), ('g3', 3)):
            idxs = np.array([IDX[low[p - 1]] for p in g[gnum]], dtype=np.uint16)
            if idxs.size == 0:
                idxs = np.zeros(1, dtype=np.uint16)
            arrs[key] = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=idxs)
        arrs['n'] = (len(g[1]), len(g[2]), len(g[3]))
        return arrs


# ----------------------------------------------------------------------------
# CPU stage: seed -> address
# ----------------------------------------------------------------------------

def _addr_worker(chunk):
    hits = []
    for tag, seed in chunk:
        k, _c = B.derive(seed, PATH)
        for comp in (True, False):
            if B.addr_p2pkh(B.pub_from_priv(k, comp)) == TARGET:
                hits.append((tag, comp))
    return hits


# ----------------------------------------------------------------------------
# modes
# ----------------------------------------------------------------------------

def do_selftest(args):
    print('== reference / CPU ==')
    mn = 'asset trial load escape symbol story bomb picnic river aerobic mystery honey'
    low = carrier(53)
    pos = [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114]
    got = ' '.join(low[p - 1] for p in pos)
    assert got == mn, got
    print('  known-good GPS reading reproduced   OK')
    assert B.checksum_ok(mn.split(), WL)
    print('  its BIP39 checksum is valid         OK')
    seed = B.mnemonic_to_seed(mn)
    print(f'  CPU pbkdf2 seed[:8] = {seed[:8].hex()}')

    print('== GPU ==')
    gpu = Gpu(args.device)
    print('  device:', gpu.describe())

    # kernel 2: PBKDF2 against hashlib, on the known mnemonic + random ones
    widx = np.array([[IDX[w] for w in mn.split()]], dtype=np.uint16)
    out = gpu.seeds_batch(widx)
    ok = bytes(out[0]) == seed
    print(f'  kernel2 PBKDF2 vs hashlib           {"OK" if ok else "MISMATCH"}')
    if not ok:
        print('    cpu', seed.hex())
        print('    gpu', bytes(out[0]).hex())
        sys.exit('PBKDF2 KERNEL IS WRONG -- do not run the search')
    rs = np.random.RandomState(7)
    batch = rs.randint(0, 2048, size=(16, 12)).astype(np.uint16)
    gout = gpu.seeds_batch(batch)
    bad = 0
    for i in range(batch.shape[0]):
        m = ' '.join(WL[int(x)] for x in batch[i])
        if bytes(gout[i]) != B.mnemonic_to_seed(m):
            bad += 1
    print(f'  kernel2 on 16 random mnemonics      {"OK" if not bad else f"{bad} MISMATCH"}')
    if bad:
        sys.exit('PBKDF2 KERNEL IS WRONG -- do not run the search')

    # kernel 1: unranking + checksum filter vs a pure-Python enumeration
    nm, bi, tt, desc = SLICES[0]
    low0 = carrier(bi)
    g = groups(low0)
    gi = gpu.group_buffers(g, low0)
    prof = profiles(g, set(tt))[0]
    a, b, c = prof
    tot = math.comb(len(g[1]), a) * math.comb(len(g[2]), b) * math.comb(len(g[3]), c)
    n = int(min(tot, 20000))
    words, ranks, raw = gpu.enumerate_batch(gi, prof, 0, n, 4096)
    # reference
    cb = math.comb(len(g[2]), b) or 1
    cc = math.comb(len(g[3]), c) or 1
    ref = []
    buf = [0] * 12
    for r in range(n):
        ra, rem = divmod(r, cb * cc)
        rb, rc = divmod(rem, cc)
        pa = [g[1][i] for i in unrank(len(g[1]), a, ra, buf[:a])] if a else []
        pb = [g[2][i] for i in unrank(len(g[2]), b, rb, buf[:b])] if b else []
        pc = [g[3][i] for i in unrank(len(g[3]), c, rc, buf[:c])] if c else []
        ws = [low0[p - 1] for p in pa + pb + pc]
        if B.checksum_ok(ws, WL):
            ref.append(tuple(IDX[w] for w in ws))
    gpuset = sorted(tuple(int(x) for x in row) for row in words)
    print(f'  kernel1 unrank+checksum: gpu={len(gpuset)} ref={len(ref)} '
          f'{"OK" if gpuset == sorted(ref) else "MISMATCH"}')
    if gpuset != sorted(ref):
        sys.exit('ENUMERATION KERNEL IS WRONG -- do not run the search')

    open(os.path.join(HERE, '.phone_selftest_ok'), 'w').write(gpu.describe() + '\n')
    print('\nSELFTEST PASSED -- --run is unlocked on this machine.')


def do_list():
    print(f'{"#":>2}  {"carrier":14} {"slice":26} {"combos":>18} {"cksum-valid":>15}')
    for i, (nm, bi, tt, d) in enumerate(SLICES):
        low = carrier(bi)
        g = groups(low)
        profs = profiles(g, set(tt))
        c = sum(math.comb(len(g[1]), a) * math.comb(len(g[2]), b) * math.comb(len(g[3]), cc)
                for a, b, cc in profs)
        print(f'{i:>2}  {nm:14} {d:26} {c:>18,} {c/16:>15,.0f}')


def do_bench(args):
    gpu = Gpu(args.device)
    print('device:', gpu.describe())
    for n in (256, 1024, args.batch):
        rs = np.random.RandomState(3)
        batch = rs.randint(0, 2048, size=(n, 12)).astype(np.uint16)
        t0 = time.time()
        gpu.seeds_batch(batch)
        dt = time.time() - t0
        print(f'  kernel2 PBKDF2 batch {n:>8}: {dt:6.2f}s -> {n/dt:10.0f} seed/s')
    print('\nCPU stage (BIP32 m/44\'/0\'/0\'/0/0 + secp256k1, per candidate):')
    seed = B.mnemonic_to_seed('abandon ' * 11 + 'about')
    t0 = time.time()
    k = 200
    for _ in range(k):
        _addr_worker([(0, seed)])
    per = (time.time() - t0) / k
    print(f'  {per*1e6:.0f} us -> {1/per:,.0f}/s per core, '
          f'~{args.procs/per:,.0f}/s on {args.procs} procs')
    print('\nThe smaller of the two rates is your throughput; the CPU stage is')
    print('usually the limiter, so more cores (or --shard across machines) helps most.')


def do_run(args):
    if not os.path.exists(os.path.join(HERE, '.phone_selftest_ok')):
        sys.exit('run --selftest first (it validates both kernels on this machine)')
    nm, bi, tt, desc = SLICES[args.slice]
    low = carrier(bi)
    g = groups(low)
    profs = profiles(g, set(tt))
    gpu = Gpu(args.device)
    print('device:', gpu.describe())
    gi = gpu.group_buffers(g, low)
    print(f'slice {args.slice}: {nm} | {desc} | profiles={len(profs)}')

    ck = os.path.join(HERE, args.checkpoint)
    done = {}
    if os.path.exists(ck):
        try:
            done = {tuple(json.loads(k)): v for k, v in json.load(open(ck))['done'].items()}
            print(f'resuming from {ck}')
        except Exception:
            print('checkpoint unreadable, starting fresh')

    shard_i, shard_n = (0, 1)
    if args.shard:
        shard_i, shard_n = (int(x) for x in args.shard.split('/'))

    pool = Pool(args.procs)
    t0 = time.time()
    total_seen = 0
    total_valid = 0
    hits = []
    last_ck = [time.time()]

    for prof in profs:
        a, b, c = prof
        cb = math.comb(len(g[2]), b) or 1
        cc = math.comb(len(g[3]), c) or 1
        tot = (math.comb(len(g[1]), a) or 1) * cb * cc
        start = done.get(prof, 0)
        r = start
        while r < tot:
            n = int(min(args.batch, tot - r))
            # shard at batch granularity
            if (r // args.batch) % shard_n != shard_i:
                r += n
                continue
            cap = max(4096, int(n // 8))
            words, ranks, raw = gpu.enumerate_batch(gi, prof, r, n, cap)
            if raw > cap:
                print(f'  WARNING: survivor buffer overflow ({raw} > {cap}); '
                      f'retrying with a larger cap', flush=True)
                words, ranks, raw = gpu.enumerate_batch(gi, prof, r, n, raw + 1024)
            total_seen += n
            total_valid += words.shape[0]
            if words.shape[0]:
                seeds = gpu.seeds_batch(words)
                pairs = [(int(ranks[i]), bytes(seeds[i])) for i in range(words.shape[0])]
                csz = max(1, len(pairs) // (args.procs * 4))
                chunks = [pairs[i:i + csz] for i in range(0, len(pairs), csz)]
                rank2words = {int(ranks[i]): words[i] for i in range(words.shape[0])}
                for res in pool.imap_unordered(_addr_worker, chunks):
                    for tag, comp in res:
                        wi = rank2words[tag]
                        mnem = ' '.join(WL[int(x)] for x in wi)
                        msg = ('\n' + '!' * 70 + '\n*** FOUND ***\n'
                               f'mnemonic : {mnem}\nslice    : {nm} / {desc}\n'
                               f'profile  : {prof}  rank {tag}\n'
                               f'path     : {PATH} compressed={comp}\n' + '!' * 70)
                        print(msg, flush=True)
                        open(os.path.join(HERE, 'FOUND.txt'), 'a').write(msg + '\n')
                        hits.append(mnem)
            r += n
            el = time.time() - t0
            if time.time() - last_ck[0] > 30:
                last_ck[0] = time.time()
                done[prof] = r
                tmp = ck + '.tmp'
                json.dump({'done': {json.dumps(list(k)): v for k, v in done.items()}},
                          open(tmp, 'w'))
                os.replace(tmp, ck)
                print(f'  profile {prof} {r:,}/{tot:,} | seen={total_seen:,} '
                      f'valid={total_valid:,} {total_seen/el:,.0f} comb/s '
                      f'hits={len(hits)}', flush=True)
        done[prof] = tot
    pool.close()
    pool.join()
    print(f'\nDONE seen={total_seen:,} checksum-valid={total_valid:,} '
          f'hits={len(hits)} elapsed={(time.time()-t0)/3600:.2f} h')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--bench', action='store_true')
    ap.add_argument('--run', action='store_true')
    ap.add_argument('--list-devices', action='store_true')
    ap.add_argument('--device', type=int, default=None)
    ap.add_argument('--slice', type=int, default=4)
    ap.add_argument('--batch', type=int, default=1 << 20)
    ap.add_argument('--procs', type=int, default=max(1, (os.cpu_count() or 4) - 1))
    ap.add_argument('--shard', default=None, help='i/N across machines')
    ap.add_argument('--checkpoint', default='phone_progress.json')
    a = ap.parse_args()
    if a.list_devices:
        print(Gpu.list_devices()); return
    if a.selftest:
        do_selftest(a); return
    if a.list:
        do_list(); return
    if a.bench:
        do_bench(a); return
    if a.run:
        do_run(a); return
    ap.print_help()


if __name__ == '__main__':
    main()
