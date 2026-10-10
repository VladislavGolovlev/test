"""Test A: contiguous 12-windows over the article's ordered BIP39 words
   (the community approach, redone with corrected text extraction).
Test B: real coordinates of landmarks named/implied in the article, applied
   via position_j = digit_j + 10*j to every carrier at small offsets.
"""
import sys, json, os, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import btclib as B, tok as T

TARGET = '1K4ezpLybootYF23TM4a8Y4NyP7auysnRo'
HERE = os.path.dirname(os.path.abspath(__file__))
WL = B.load_wordlist('/home/user/test/word.txt')
WSET = set(WL)
BLOCKS = json.load(open(os.path.join(HERE, 'blocks.json')))

PATHS = ["m/44'/0'/0'/0/0", "m/0/0", "m/0'/0/0", "m/44'/0'/0'/0/1", "m/0'/0'/0'",
         "m/44'/0'/0'/1/0", "m/0", "m/0'", "m/44'/0'/1'/0/0", "m/44'/0'/0'/0/2",
         "m/0'/0", "m/1/0", "m/44'/0'/0'", "m/0'/0'"]


def check(mn):
    seed = B.mnemonic_to_seed(mn)
    out = []
    for p in PATHS:
        k, _c = B.derive(seed, p)
        for comp in (True, False):
            if B.addr_p2pkh(B.pub_from_priv(k, comp)) == TARGET:
                out.append((p, comp))
    return out


def txt(idxs):
    return ' '.join(BLOCKS[i]['text'] for i in idxs)

STREAMS = {
    'all': txt(range(0, 60)),
    'body': txt(range(4, 60)),
    'p_only': txt([i for i in range(4, 60) if BLOCKS[i]['tag'] in ('p', 'blockquote')]),
    'nocap': txt([i for i in range(4, 60) if BLOCKS[i]['tag'] != 'figcaption']),
    'noheads': txt([i for i in range(4, 60) if BLOCKS[i]['tag'] not in ('h1', 'h2', 'h3')]),
    'rev': txt(range(4, 14)),
}
for i in range(4, 60):
    if BLOCKS[i]['tag'] in ('p', 'pre', 'blockquote', 'figcaption'):
        STREAMS['para_%d' % i] = BLOCKS[i]['text']
TOKVAR = [(dp, sh, kn) for dp in (True, False) for sh in (False, True) for kn in (True, False)]

# ---------------- Test A ----------------
print('=== TEST A: contiguous windows over ordered BIP39 words ===')
tested = set(); hits = []; n_win = 0
for name, text in STREAMS.items():
    for dp, sh, kn in TOKVAR:
        toks = T.tokenize(text, drop_punct_only=dp, split_hyphen=sh, keep_numbers=kn)
        bip = [t.lower().strip("'") for t in toks if t.lower().strip("'") in WSET]
        for s in range(0, max(0, len(bip) - 11)):
            mn = ' '.join(bip[s:s + 12])
            if mn in tested:
                continue
            tested.add(mn); n_win += 1
            h = check(mn)
            if h:
                hits.append((mn, name, s, h)); print('*** MATCH', mn, name, s, h, flush=True)
print(f'unique windows tested: {n_win}  valid-checksum among them: '
      f'{sum(1 for m in tested if B.checksum_ok(m.split(), WL))}  hits: {len(hits)}')

# ---------------- Test B ----------------
LANDMARKS = [
    ('Qingdao', 36.0671, 120.3826), ('Qingdao alt', 36.0986, 120.3719),
    ('Zhanqiao Pier', 36.0586, 120.3155),
    ('Taipei', 25.0330, 121.5654), ('Taipei101', 25.0338, 121.5645),
    ('Taiwan', 23.6978, 120.9605),
    ('Beijing', 39.9042, 116.4074), ('ForbiddenCity', 39.9163, 116.3972),
    ('Tiananmen', 39.9055, 116.3976), ('Shanghai', 31.2304, 121.4737),
    ('GreatWall', 40.3587, 116.0167), ('TerracottaArmy', 34.3841, 109.2785),
    ('HongKong', 22.3193, 114.1694), ('China', 35.8617, 104.1954),
    ('Toronto', 43.6532, 79.3832), ('Vancouver', 49.2827, 123.1207),
    ('Ottawa', 45.4215, 75.6972), ('Montreal', 45.5017, 73.5673),
    ('Canada', 56.1304, 106.3468),
    ('JesusCollegeOxford', 51.7533, 1.2573), ('Oxford', 51.7520, 1.2577),
    ('MountVernon', 38.7076, 77.0861), ('SupremeCourt', 38.8906, 77.0044),
    ('Caracas', 10.4806, 66.9036), ('Venezuela', 6.4238, 66.5897),
    ('Harare', 17.8252, 31.0335), ('Zimbabwe', 19.0154, 29.1549),
    ('Giza', 29.9792, 31.1342), ('Athens', 37.9838, 23.7275),
    ('Frankfurt', 50.1109, 8.6821), ('Vatican', 41.9029, 12.4534),
    ('Trittenheim', 49.8231, 6.8972), ('Wurzburg', 49.7913, 9.9534),
    ('SponheimAbbey', 49.8000, 7.7000),
]

def digit_variants(lat, lon):
    out = set()
    for ld in range(2, 8):
        for od in range(2, 8):
            s = (f'%.{ld}f' % abs(lat)).replace('.', '') + (f'%.{od}f' % abs(lon)).replace('.', '')
            if len(s) >= 12:
                out.add(s[:12])
    return out

print('\n=== TEST B: real landmark coordinates ===')
nb = 0; hitsB = []; allbip = []
for name, text in STREAMS.items():
    for dp, sh, kn in TOKVAR:
        toks = T.tokenize(text, drop_punct_only=dp, split_hyphen=sh, keep_numbers=kn)
        n = len(toks)
        for lname, lat, lon in LANDMARKS:
            for ds in digit_variants(lat, lon):
                digs = [int(c) for c in ds]
                for off in range(0, 6):
                    pos = [off + d + 10 * j for j, d in enumerate(digs)]
                    if pos[0] < 1 or pos[-1] > n:
                        continue
                    nb += 1
                    w = [toks[p - 1].lower().strip("'") for p in pos]
                    if any(x not in WSET for x in w):
                        continue
                    mn = ' '.join(w)
                    ck = B.checksum_ok(w, WL)
                    allbip.append((mn, name, lname, ds, off, ck))
                    h = check(mn)
                    if h:
                        hitsB.append((mn, name, lname, ds, off, h))
                        print('*** MATCH', mn, name, lname, ds, off, h, flush=True)
print(f'coordinate readings tried: {nb:,}  all-BIP39 results: {len(allbip)}  hits: {len(hitsB)}')
for r in allbip[:40]:
    print('  12xBIP39:', r)
