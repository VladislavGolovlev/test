"""Definitive GPS-method solver for the 'Securing Wealth in Poetry' puzzle.

Model (validated against the article's own GPS example):
   position_j = digit_j + 10*j    (1-indexed word position in the carrier text)
=> seed word j must be a BIP39 word somewhere in decade window [10j, 10j+9].

We sweep carrier streams x tokenizations x story-start offsets, enumerate all
decade-consistent 12-word combinations, keep those with a valid BIP39 checksum,
and compare derived P2PKH addresses against the target.
"""
import sys, json, itertools, hashlib, time, os
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import btclib as B, tok as T

TARGET = '1K4ezpLybootYF23TM4a8Y4NyP7auysnRo'
WL = B.load_wordlist('/home/user/test/word.txt')
IDX = {w: i for i, w in enumerate(WL)}
SHA = hashlib.sha256
BLOCKS = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocks.json')))

PATHS = ["m/44'/0'/0'/0/0", "m/0/0", "m/0'/0/0", "m/44'/0'/0'/0/1", "m/0'/0'/0'"]


def streams():
    def txt(idxs):
        return ' '.join(BLOCKS[i]['text'] for i in idxs)
    BODY = range(4, 60)
    S = {}
    S['all']     = txt(range(0, 60))
    S['body']    = txt(BODY)
    S['p_only']  = txt([i for i in BODY if BLOCKS[i]['tag'] in ('p', 'blockquote')])
    S['noheads'] = txt([i for i in BODY if BLOCKS[i]['tag'] not in ('h1', 'h2', 'h3')])
    S['nocap']   = txt([i for i in BODY if BLOCKS[i]['tag'] != 'figcaption'])
    S['p_pre']   = txt([i for i in BODY if BLOCKS[i]['tag'] in ('p', 'blockquote', 'pre')])
    S['rev']     = txt(range(4, 14))
    S['rev_nocap'] = txt([i for i in range(4, 14) if BLOCKS[i]['tag'] != 'figcaption'])
    S['rev_h']   = txt(range(3, 14))
    S['title']   = txt(range(0, 4))
    return S

TOKVAR = [(dp, sh, kn) for dp in (True, False) for sh in (False, True) for kn in (True, False)]

# build all (label, token-index-array) configs once
CONFIGS = []
for _name, _text in streams().items():
    for dp, sh, kn in TOKVAR:
        _toks = T.tokenize(_text, drop_punct_only=dp, split_hyphen=sh, keep_numbers=kn)
        _wi = [IDX.get(t.lower().strip("'"), -1) for t in _toks]
        CONFIGS.append((f'{_name}|dp{int(dp)}sh{int(sh)}kn{int(kn)}', _wi))


def scan_offset(args):
    """Enumerate + check one (config, offset). Returns (combos, valid, hits)."""
    ci, off = args
    label, wi = CONFIGS[ci]
    n = len(wi)
    cands = []
    tot = 1
    for j in range(12):
        opts = []
        base = off + 10 * j
        for d in range(10):
            p = base + d
            if 1 <= p <= n and wi[p - 1] >= 0:
                opts.append((d, wi[p - 1]))
        if not opts:
            return (0, 0, [])
        cands.append(opts)
        tot *= len(opts)
    if tot > 4_000_000:
        return (0, 0, [])
    valid = 0
    hits = []
    for combo in itertools.product(*cands):
        bits = 0
        for _, v in combo:
            bits = (bits << 11) | v
        ent = (bits >> 4).to_bytes(16, 'big')
        if (bits & 0xF) != (SHA(ent).digest()[0] >> 4):
            continue
        valid += 1
        words = [WL[v] for _, v in combo]
        mn = ' '.join(words)
        seed = B.mnemonic_to_seed(mn)
        for p in PATHS:
            k, _c = B.derive(seed, p)
            for comp in (True, False):
                if B.addr_p2pkh(B.pub_from_priv(k, comp)) == TARGET:
                    digits = ''.join(str(d) for d, _ in combo)
                    hits.append((mn, label, off, digits, p, comp))
    return (tot, valid, hits)


def main(off_lo, off_hi, procs=4):
    jobs = []
    for ci, (label, wi) in enumerate(CONFIGS):
        hi = min(off_hi, len(wi) - 110)
        for off in range(off_lo, hi + 1):
            jobs.append((ci, off))
    print(f'configs={len(CONFIGS)} jobs={len(jobs)} offsets={off_lo}..{off_hi}', flush=True)
    t0 = time.time()
    C = V = 0
    allhits = []
    with Pool(procs) as pool:
        for i, (c, v, h) in enumerate(pool.imap_unordered(scan_offset, jobs, chunksize=8)):
            C += c; V += v
            if h:
                allhits += h
                for x in h:
                    print('\n*** ADDRESS MATCH ***', x, flush=True)
            if i % 2000 == 0:
                print(f'  {i}/{len(jobs)} combos={C:,} valid={V:,} [{time.time()-t0:.0f}s]', flush=True)
    print(f'DONE offsets {off_lo}..{off_hi}: combos={C:,} checksum_valid={V:,} '
          f'hits={len(allhits)} elapsed={time.time()-t0:.0f}s', flush=True)
    return allhits


if __name__ == '__main__':
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    main(lo, hi)
