"""Minimal fast BIP32/BIP39 -> legacy P2PKH address toolkit."""
import hashlib, hmac, unicodedata
from coincurve import PublicKey
from coincurve.keys import PrivateKey

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def b58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num = int.from_bytes(payload + chk, 'big')
    out = ''
    while num:
        num, r = divmod(num, 58)
        out = B58[r] + out
    for b in payload + chk:
        if b == 0:
            out = '1' + out
        else:
            break
    return out

def h160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def pub_from_priv(k: bytes, compressed=True) -> bytes:
    return PrivateKey(k).public_key.format(compressed)

def addr_p2pkh(pub: bytes) -> str:
    return b58check(b'\x00' + h160(pub))

def master(seed: bytes, key=b'Bitcoin seed'):
    I = hmac.new(key, seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def ckd(k: bytes, c: bytes, idx: int):
    if idx >= 0x80000000:
        data = b'\x00' + k + idx.to_bytes(4, 'big')
    else:
        data = pub_from_priv(k) + idx.to_bytes(4, 'big')
    I = hmac.new(c, data, hashlib.sha512).digest()
    kc = (int.from_bytes(I[:32], 'big') + int.from_bytes(k, 'big')) % N
    return kc.to_bytes(32, 'big'), I[32:]

def parse_path(path: str):
    out = []
    for p in path.split('/'):
        p = p.strip()
        if p in ('m', 'M', ''):
            continue
        if p.endswith(("'", 'h', 'H')):
            out.append(int(p[:-1]) + 0x80000000)
        else:
            out.append(int(p))
    return out

def derive(seed: bytes, path: str):
    k, c = master(seed)
    for i in parse_path(path):
        k, c = ckd(k, c, i)
    return k, c

def mnemonic_to_seed(words: str, passphrase: str = '') -> bytes:
    m = unicodedata.normalize('NFKD', words).encode()
    s = unicodedata.normalize('NFKD', 'mnemonic' + passphrase).encode()
    return hashlib.pbkdf2_hmac('sha512', m, s, 2048, 64)

WORDS = None
def load_wordlist(path):
    global WORDS
    with open(path) as f:
        WORDS = [w.strip() for w in f if w.strip()]
    return WORDS

def checksum_ok(words_list, wl=None):
    wl = wl or WORDS
    n = len(words_list)
    if n % 3 or not (12 <= n <= 24):
        return False
    try:
        idxs = [wl.index(w) for w in words_list]
    except ValueError:
        return False
    bits = ''.join(format(i, '011b') for i in idxs)
    ent_len = n * 32 // 3
    cs_len = n // 3
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, 'big')
    h = format(hashlib.sha256(ent).digest()[0], '08b')[:cs_len]
    return bits[ent_len:] == h
