"""Phone-method search: ordered 12-subsets of a carrier's BIP39 words.

WHY THIS IS THE RIGHT TARGET
----------------------------
The article's "Story & phone number" method scatters the seed words through a
purpose-written story and keeps the positional key OFF the page:

    "Two or three phone numbers are then written after the story is
     constructed... These should be written on a different page to remove any
     connection between the text and the numbers."

So the key is deliberately unrecoverable from the article, and the closing hint
is worded to match exactly -- it promises every **word**, never the numbers:

    "If you've read this far, you've read every word required to access a
     wallet with .03 BTC."

Brute-forcing the positions is therefore the intended-difficulty path.

Two facts say the carrier is one of the two worked examples rather than the
article's prose:
  * They are purpose-written and seed-dense: 41% and 31% of their tokens are
    BIP39 words, versus 19% for the Revolution story (natural prose).
  * The phone example's own published numbers decode to an INVALID phrase
    (10/12 BIP39 words: "a" and "payment" are not BIP39) -- consistent with the
    method's stated use of "true and decoy seed phrases". The published reading
    is a decoy.

And the author's own tooling is BIP39, not Electrum: the GPS example, which he
constructed himself, decodes to a 12-word BIP39 mnemonic with a VALID checksum
(a 1-in-16 event by chance). The article's printed "witch collapse ..." phrase
is an Electrum-wordlist phrase, but it is a stock example found in 309 files on
GitHub, so it says nothing about what he used for his own wallet.

THE PRUNE
---------
Positions are the greedy ascending read of the concatenated phone digits, so
the TOTAL DIGIT COUNT of the 12 positions equals the digits of 2-3 phone
numbers. Verified on the published example: positions
2,6,9,18,22,25,45,70,86,100,113,116 have digit-lengths 1,1,1,2,2,2,2,2,2,3,3,3
= 24 digits = two 12-digit numbers.

Requiring a 3-phone-number profile (30-39 digits) prunes the space 165x.

    carrier         slice                    checksum-valid   4-core CPU
    GPS example     3 phones (30-39 digits)         577,417      ~4 min
    GPS example     24 digits (as published)     13,407,908      ~1.2 h
    GPS example     2 phones (20-26 digits)      75,538,332      ~6.8 h
    phone example   3 phones (30-39 digits)      59,937,205      ~5.4 h
    phone example   24 digits (as published)  1,665,056,404      ~150 h  (GPU)
    phone example   unconstrained             9,922,086,869      ~896 h  (GPU)

Usage:
    python3 subset_phone.py --list
    python3 subset_phone.py --run            # all slices, cheapest first
    python3 subset_phone.py --run --max-hours 6
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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import btclib as B
import tok as T

TARGET = '1K4ezpLybootYF23TM4a8Y4NyP7auysnRo'
WL = B.load_wordlist(os.path.join(os.path.dirname(HERE), 'word.txt'))
IDX = {w: i for i, w in enumerate(WL)}
WSET = set(WL)
SHA = hashlib.sha256
BLOCKS = json.load(open(os.path.join(HERE, 'article_blocks.json'), encoding='utf-8'))

PATHS = ["m/44'/0'/0'/0/0", "m/0/0", "m/0'/0/0", "m/44'/0'/0'/0/1", "m/0'/0'/0'"]


def carrier(block_idx):
    """The example body, with the trailing number annotations stripped."""
    body = BLOCKS[block_idx]['text'].split('Example:', 1)[-1].split('-------------')[0]
    low = [t.lower().strip("'") for t in T.tokenize(body)]
    return low


def groups(low):
    """BIP39-word positions split by decimal digit-length (1-9, 10-99, 100+).

    Positions in a lower group are always numerically smaller, so a merged
    pick stays in ascending text order without re-sorting.
    """
    g = {1: [], 2: [], 3: []}
    for i, w in enumerate(low):
        if w in WSET:
            p = i + 1
            g[len(str(p))].append(p)
    return g


def profiles(g, totals):
    """(a,b,c) picks per digit-group whose total digit count is in `totals`."""
    out = []
    for a in range(0, min(len(g[1]), 12) + 1):
        for b in range(0, min(len(g[2]), 12 - a) + 1):
            c = 12 - a - b
            if c < 0 or c > len(g[3]):
                continue
            if a + 2 * b + 3 * c in totals:
                out.append((a, b, c))
    return out


def count(g, profs):
    return sum(math.comb(len(g[1]), a) * math.comb(len(g[2]), b) * math.comb(len(g[3]), c)
               for a, b, c in profs)


SLICES = [
    ('GPS example',   53, tuple(range(30, 40)), '3 phones (30-39 digits)'),
    ('GPS example',   53, (24,),                '24 digits (as published)'),
    ('GPS example',   53, tuple(range(20, 27)), '2 phones (20-26 digits)'),
    ('phone example', 51, tuple(range(30, 40)), '3 phones (30-39 digits)'),
    ('phone example', 51, (24,),                '24 digits (as published)'),
    ('phone example', 51, tuple(range(20, 27)), '2 phones (20-26 digits)'),
]

_LOW = None


def _init(low):
    global _LOW
    _LOW = low


def _chunk(task):
    """task = (a_pick, b_head, b_tail, c_group, b, c).

    Work is split on the FIRST element of the b-pick (b_head) so that there are
    ~len(g[2]) tasks per (profile, a-pick) instead of one huge task -- the
    1-digit group has only a handful of positions, so splitting on it alone
    leaves almost no parallelism on the large slices.
    """
    apick, bhead, btail, cg, b, c = task
    low = _LOW
    hits = []
    n = 0
    pre = [low[p - 1] for p in apick]
    if b == 0:
        bpicks = [()] if bhead is None else []
    else:
        bpicks = ((bhead,) + rest for rest in itertools.combinations(btail, b - 1))
    for bpick in bpicks:
        mid = [low[p - 1] for p in bpick]
        for cpick in itertools.combinations(cg, c):
            n += 1
            words = pre + mid + [low[p - 1] for p in cpick]
            bits = 0
            for w in words:
                bits = (bits << 11) | IDX[w]
            ent = (bits >> 4).to_bytes(16, 'big')
            if (bits & 0xF) != (SHA(ent).digest()[0] >> 4):
                continue
            mn = ' '.join(words)
            seed = B.mnemonic_to_seed(mn)
            for p in PATHS:
                k, _c = B.derive(seed, p)
                for comp in (True, False):
                    if B.addr_p2pkh(B.pub_from_priv(k, comp)) == TARGET:
                        hits.append((mn, apick + bpick + cpick, p, comp))
    return n, hits


def run_slice(name, bidx, totals, desc, procs, deadline):
    low = carrier(bidx)
    g = groups(low)
    profs = profiles(g, set(totals))
    tot = count(g, profs)
    print(f'\n=== {name} | {desc} ===', flush=True)
    print(f'    tokens={len(low)} bip39={sum(len(v) for v in g.values())} '
          f'profiles={len(profs)} combos={tot:,} (~{tot/16:,.0f} checksum-valid)', flush=True)
    tasks = []
    g2, g3 = tuple(g[2]), tuple(g[3])
    for a, b, c in profs:
        for apick in itertools.combinations(g[1], a):
            if b == 0:
                tasks.append((apick, None, (), g3, 0, c))
                continue
            for i in range(len(g2) - b + 1):
                tasks.append((apick, g2[i], g2[i + 1:], g3, b, c))
    t0 = time.time()
    seen = 0
    hits = []
    last = [0.0]
    print(f'    parallel tasks={len(tasks):,}', flush=True)
    with Pool(procs, initializer=_init, initargs=(low,)) as pool:
        for n, h in pool.imap_unordered(_chunk, tasks, chunksize=1):
            seen += n
            for x in h:
                hits.append(x)
                msg = ('\n' + '!' * 70 + '\n*** FOUND ***\n'
                       f'mnemonic  : {x[0]}\npositions : {list(x[1])}\n'
                       f'path      : {x[2]} compressed={x[3]}\n' + '!' * 70)
                print(msg, flush=True)
                open(os.path.join(HERE, 'FOUND.txt'), 'a').write(msg + '\n')
            el = time.time() - t0
            if el > 0 and seen and time.time() - last[0] > 20:
                last[0] = time.time()
                print(f'    {seen:,}/{tot:,} ({100*seen/tot:.2f}%) '
                      f'{seen/el:,.0f} combos/s eta {(tot-seen)/max(seen/el,1e-9)/3600:.2f} h '
                      f'hits={len(hits)}', flush=True)
            if deadline and time.time() > deadline:
                print('    time limit reached, stopping this slice', flush=True)
                break
    print(f'    slice done: {seen:,} combos in {time.time()-t0:.0f}s hits={len(hits)}', flush=True)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--run', action='store_true')
    ap.add_argument('--procs', type=int, default=max(1, (os.cpu_count() or 4)))
    ap.add_argument('--max-hours', type=float, default=0)
    ap.add_argument('--only', type=int, default=None, help='run just slice N from --list')
    a = ap.parse_args()

    if a.list or not a.run:
        print(f'{"#":>2}  {"carrier":14} {"slice":26} {"combos":>18} {"cksum-valid":>15}')
        for i, (nm, bi, tt, d) in enumerate(SLICES):
            low = carrier(bi)
            g = groups(low)
            c = count(g, profiles(g, set(tt)))
            print(f'{i:>2}  {nm:14} {d:26} {c:>18,} {c/16:>15,.0f}')
        if not a.run:
            return

    deadline = time.time() + a.max_hours * 3600 if a.max_hours else None
    allhits = []
    order = [a.only] if a.only is not None else range(len(SLICES))
    for i in order:
        nm, bi, tt, d = SLICES[i]
        allhits += run_slice(nm, bi, tt, d, a.procs, deadline)
        if deadline and time.time() > deadline:
            print('\nglobal time limit reached', flush=True)
            break
    print(f'\nTOTAL hits={len(allhits)}', flush=True)


if __name__ == '__main__':
    main()
