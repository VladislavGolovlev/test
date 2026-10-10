"""Old Electrum (v1) deterministic wallet: seed phrase -> addresses.

Algorithm (Electrum 1.x):
  1. 12 words from the 1626-word list -> 32-char hex seed (mnemonic_decode)
  2. master private key = stretch_key(hex_seed_ascii):
         x = s ; repeat 100000x: x = sha256(x + s)
  3. master public key = UNCOMPRESSED pubkey bytes (x||y, 64 bytes, no 0x04)
  4. for address n / change c:
         z = sha256d(b"%d:%d:" % (n, c) + mpk64)
         secexp = (master_secret + z) mod N
         address = P2PKH of the UNCOMPRESSED pubkey
"""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import btclib as B

N = B.N
WORDS = [w.strip() for w in open('/home/user/test/electrum_words.txt') if w.strip()]
NW = len(WORDS)
WIDX = {w: i for i, w in enumerate(WORDS)}
assert NW == 1626, NW


def mnemonic_decode(words):
    out = ''
    for i in range(len(words) // 3):
        w1, w2, w3 = words[3 * i:3 * i + 3]
        try:
            i1 = WIDX[w1]; i2 = WIDX[w2] % NW; i3 = WIDX[w3] % NW
        except KeyError:
            return None
        x = i1 + NW * ((i2 - i1) % NW) + NW * NW * ((i3 - i2) % NW)
        out += '%08x' % x
    return out


def mnemonic_encode(hexseed):
    out = []
    for i in range(len(hexseed) // 8):
        word = hexseed[8 * i:8 * i + 8]
        x = int(word, 16)
        w1 = x % NW
        w2 = ((x // NW) + w1) % NW
        w3 = ((x // NW // NW) + w2) % NW
        out += [WORDS[w1], WORDS[w2], WORDS[w3]]
    return out


def stretch_key(seed_ascii: bytes) -> bytes:
    x = seed_ascii
    for _ in range(100000):
        x = hashlib.sha256(x + seed_ascii).digest()
    return x


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def master_from_seed(hexseed: str):
    msec_b = stretch_key(hexseed.encode('ascii'))
    msec = int.from_bytes(msec_b, 'big')
    mpk64 = B.pub_from_priv(msec_b, compressed=False)[1:]  # strip 0x04
    return msec, mpk64


def address_at(msec: int, mpk64: bytes, n: int, change: int = 0, compressed=False) -> str:
    z = int.from_bytes(sha256d(b'%d:%d:' % (n, change) + mpk64), 'big')
    sec = (msec + z) % N
    pub = B.pub_from_priv(sec.to_bytes(32, 'big'), compressed=compressed)
    return B.addr_p2pkh(pub)


def addresses(words, count=5, changes=(0, 1), both_comp=True):
    hs = mnemonic_decode(words)
    if hs is None:
        return {}
    msec, mpk = master_from_seed(hs)
    out = {}
    for c in changes:
        for n in range(count):
            for comp in ((False, True) if both_comp else (False,)):
                out[(c, n, comp)] = address_at(msec, mpk, n, c, comp)
    return out


if __name__ == '__main__':
    # Electrum 1.x test vector (from Electrum's own test suite)
    seed_words = ('powerful random nobody notice nothing important '
                  'anyway look away hidden message over').split()
    print('words all in list:', all(w in WIDX for w in seed_words))
    hs = mnemonic_decode(seed_words)
    print('hex seed:', hs)
    print('encode round-trip ok:', mnemonic_encode(hs) == seed_words)
    msec, mpk = master_from_seed(hs)
    print('mpk:', mpk.hex())
    print('expected mpk: e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df'
          '9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')
    a0 = address_at(msec, mpk, 0, 0)
    print('address 0:', a0)
    print('expected  : 1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo')
