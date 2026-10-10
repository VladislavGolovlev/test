"""Generate candidate OLD-ELECTRUM seed phrases from the article.

Old Electrum v1 seeds have NO checksum, so candidates cannot be pre-filtered
cryptographically; and key stretching costs 100k SHA256 (~tens of ms), so the
candidate set must be kept tight.  We therefore collect, cheaply and without
any key derivation, every 12-word sequence that is wholly inside the 1626-word
Electrum list, from these sources:

  A  real landmark coordinates -> position_j = digit_j + 10*j
  B  the two number lists published in the article
  C  contiguous 12-windows over the text's Electrum-word subsequence
  D  free decade enumeration (all coordinates) at story-start offsets

Output: elec_cands.txt, deduplicated.
"""
import sys, json, os, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tok as T

HERE = os.path.dirname(os.path.abspath(__file__))
EW = [w.strip() for w in open('/home/user/test/electrum_words.txt') if w.strip()]
ESET = set(EW)
BLOCKS = json.load(open(os.path.join(HERE, 'blocks.json')))


def txt(idxs):
    return ' '.join(BLOCKS[i]['text'] for i in idxs)

STREAMS = {
    'all': txt(range(0, 60)), 'body': txt(range(4, 60)),
    'p_only': txt([i for i in range(4, 60) if BLOCKS[i]['tag'] in ('p', 'blockquote')]),
    'nocap': txt([i for i in range(4, 60) if BLOCKS[i]['tag'] != 'figcaption']),
    'noheads': txt([i for i in range(4, 60) if BLOCKS[i]['tag'] not in ('h1', 'h2', 'h3')]),
    'p_pre': txt([i for i in range(4, 60) if BLOCKS[i]['tag'] in ('p', 'blockquote', 'pre')]),
    'rev': txt(range(4, 14)),
    'rev_nocap': txt([i for i in range(4, 14) if BLOCKS[i]['tag'] != 'figcaption']),
    'rev_h': txt(range(3, 14)),
}
for i in range(4, 60):
    if BLOCKS[i]['tag'] in ('p', 'pre', 'blockquote', 'figcaption'):
        STREAMS['para_%d' % i] = BLOCKS[i]['text']

LANDMARKS = [
    ('Qingdao', 36.0671, 120.3826), ('QingdaoAlt', 36.0986, 120.3719),
    ('Zhanqiao', 36.0586, 120.3155), ('QingdaoPort', 36.0878, 120.3119),
    ('Taipei', 25.0330, 121.5654), ('Taipei101', 25.0338, 121.5645),
    ('Taiwan', 23.6978, 120.9605), ('Keelung', 25.1276, 121.7392),
    ('Beijing', 39.9042, 116.4074), ('ForbiddenCity', 39.9163, 116.3972),
    ('Tiananmen', 39.9055, 116.3976), ('Shanghai', 31.2304, 121.4737),
    ('GreatWall', 40.3587, 116.0167), ('Terracotta', 34.3841, 109.2785),
    ('HongKong', 22.3193, 114.1694), ('China', 35.8617, 104.1954),
    ('Toronto', 43.6532, 79.3832), ('Vancouver', 49.2827, 123.1207),
    ('Ottawa', 45.4215, 75.6972), ('Montreal', 45.5017, 73.5673),
    ('Canada', 56.1304, 106.3468), ('Victoria', 48.4284, 123.3656),
    ('JesusCollege', 51.7533, 1.2573), ('Oxford', 51.7520, 1.2577),
    ('MountVernon', 38.7076, 77.0861), ('SupremeCourt', 38.8906, 77.0044),
    ('Caracas', 10.4806, 66.9036), ('Venezuela', 6.4238, 66.5897),
    ('Harare', 17.8252, 31.0335), ('Zimbabwe', 19.0154, 29.1549),
    ('Giza', 29.9792, 31.1342), ('Athens', 37.9838, 23.7275),
    ('Frankfurt', 50.1109, 8.6821), ('Vatican', 41.9029, 12.4534),
    ('Trittenheim', 49.8231, 6.8972), ('Wurzburg', 49.7913, 9.9534),
    ('Sponheim', 49.8000, 7.7000),
]

TOKVAR = [(dp, sh, kn) for dp in (True, False) for sh in (False, True) for kn in (True, False)]
cands = {}


def add(words, prov):
    if len(words) == 12 and all(w in ESET for w in words):
        cands.setdefault(' '.join(words), prov)


def coord_digit_strings(lat, lon):
    out = set()
    for ld in range(2, 8):
        for od in range(2, 8):
            s = (f'%.{ld}f' % abs(lat)).replace('.', '') + (f'%.{od}f' % abs(lon)).replace('.', '')
            if len(s) >= 12:
                out.add(s[:12])
    return out

PUB = {'gps_list': [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114],
       'phone_list': [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]}

for sname, text in STREAMS.items():
    for dp, sh, kn in TOKVAR:
        toks = T.tokenize(text, drop_punct_only=dp, split_hyphen=sh, keep_numbers=kn)
        low = [t.lower().strip("'") for t in toks]
        n = len(low)
        tv = f'dp{int(dp)}sh{int(sh)}kn{int(kn)}'

        # --- A: landmark coordinates
        for lname, la, lo in LANDMARKS:
            for ds in coord_digit_strings(la, lo):
                digs = [int(c) for c in ds]
                for off in range(0, 6):
                    pos = [off + d + 10 * j for j, d in enumerate(digs)]
                    if pos[0] < 1 or pos[-1] > n:
                        continue
                    add([low[p - 1] for p in pos], f'A|{sname}|{tv}|{lname}|{ds}|off{off}')

        # --- B: published number lists (raw stream and filtered-word list)
        filt = [w for w in low if w in ESET]
        for pname, nums in PUB.items():
            for off in (-1, 0, 1):
                pos = [p + off for p in nums]
                if pos[0] >= 1 and pos[-1] <= n:
                    add([low[p - 1] for p in pos], f'B|{sname}|{tv}|{pname}|raw|off{off}')
                if pos[0] >= 1 and pos[-1] <= len(filt):
                    add([filt[p - 1] for p in pos], f'B|{sname}|{tv}|{pname}|filt|off{off}')

        # --- C: contiguous windows over the Electrum-word subsequence
        for s in range(0, max(0, len(filt) - 11)):
            add(filt[s:s + 12], f'C|{sname}|{tv}|win{s}')

        # --- D: free decade enumeration at story-start offsets
        for off in range(0, 16):
            opts = []
            ok = True
            for j in range(12):
                base = off + 10 * j
                o = [low[base + d - 1] for d in range(10)
                     if 1 <= base + d <= n and low[base + d - 1] in ESET]
                if not o:
                    ok = False
                    break
                opts.append(o)
            if not ok:
                continue
            tot = 1
            for o in opts:
                tot *= len(o)
            if tot > 60000:
                continue
            for combo in itertools.product(*opts):
                add(list(combo), f'D|{sname}|{tv}|off{off}')

with open(os.path.join(HERE, 'elec_cands.txt'), 'w') as f:
    for m, p in cands.items():
        f.write(f'{m}\t{p}\n')
from collections import Counter
print('unique all-Electrum 12-word candidates:', len(cands))
print(Counter(p.split('|')[0] for p in cands.values()))
