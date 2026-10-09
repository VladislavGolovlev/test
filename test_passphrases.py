import hashlib
import hmac
import sys
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import ecdsa
import base58

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = Path(r"c:\Users\Vladislav\Desktop\Новая папка")
CANDIDATES_FILE = BASE_DIR / "valid_gps_candidates.txt"
TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"

DERIVATION_PATHS = [
    "m/44'/0'/0'/0/0",
    "m/44'/0'/0'/0/1",
    "m/0'/0'/0'",
    "m/0/0",
    "m/44'/0'/0'/0",
]

PASSPHRASES = [
    "",
    "Trithemius",
    "trithemius",
    "Poetry",
    "poetry",
    "Securing Wealth in Poetry",
    "securing wealth in poetry",
    "Revolution",
    "revolution",
    "Fiat",
    "fiat",
    "Qingdao",
    "qingdao",
    "Taiwan",
    "taiwan",
    "ye-ye",
    "yeye",
    "1949",
    "yuanbao",
    "tael",
    "gold",
    "Steganographia",
    "steganographia",
    "Barth Bailey",
    "Dan Mason",
    "Hardwarewallets.net",
    "M.7.7 Gall.",
    "M.7.7",
    "sympathetic stain",
    "0.03",
    ".03",
    "Good luck!",
    "Good luck",
]

SECP256K1_ORDER = ecdsa.curves.SECP256k1.order

def get_pubkey(priv_bytes: bytes, compressed: bool = True) -> bytes:
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if not compressed:
        return b"\x04" + vk.to_string()
    pub = vk.to_string()
    prefix = b"\x02" if pub[-1] % 2 == 0 else b"\x03"
    return prefix + pub[:32]

def ckd_priv(parent_k: bytes, parent_c: bytes, index: int):
    is_hardened = index >= 0x80000000
    if is_hardened:
        data = b"\x00" + parent_k + index.to_bytes(4, "big")
    else:
        pub = get_pubkey(parent_k, compressed=True)
        data = pub + index.to_bytes(4, "big")
    I = hmac.new(parent_c, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    parse_il = int.from_bytes(IL, "big")
    if parse_il >= SECP256K1_ORDER:
        return None, None
    k_i = (parse_il + int.from_bytes(parent_k, "big")) % SECP256K1_ORDER
    if k_i == 0:
        return None, None
    return k_i.to_bytes(32, "big"), IR

def derive_address(seed: bytes, path: str, compressed: bool = True) -> str:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]
    parts = path.strip().split("/")[1:]
    cur_k, cur_c = master_k, master_c
    for p in parts:
        if p.endswith("'"):
            idx = int(p[:-1]) + 0x80000000
        else:
            idx = int(p)
        cur_k, cur_c = ckd_priv(cur_k, cur_c, idx)
        if cur_k is None:
            return ""
    pubkey = get_pubkey(cur_k, compressed=compressed)
    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return base58.b58encode_check(b"\x00" + ripe).decode("utf-8")

def check_phrase_passphrases(line: str):
    phrase, meta = line.split("|", 1)
    phrase = phrase.strip()
    meta = meta.strip()
    words = phrase.split()
    if len(words) != 12:
        return None

    # Проверяем все пароли
    for pw in PASSPHRASES:
        salt = ("mnemonic" + pw).encode("utf-8")
        seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
        for path in DERIVATION_PATHS:
            for comp in [True, False]:
                addr = derive_address(seed, path, compressed=comp)
                if addr == TARGET_ADDRESS:
                    return phrase, pw, path, comp, meta
    return None

def main():
    start_time = time.time()
    print("=" * 75)
    print("ТЕСТИРОВАНИЕ РАСШИРЕННЫХ ПАРОЛЕЙ (PASSPHRASES) ДЛЯ ВСЕХ ВАЛИДНЫХ ФРАЗ")
    print(f"Целевой адрес: {TARGET_ADDRESS}")
    print(f"Число паролей: {len(PASSPHRASES)}")
    print("=" * 75)

    with open(CANDIDATES_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    print(f"Загружено валидных мнемоник из {CANDIDATES_FILE}: {len(lines)}")

    # Фильтруем сначала фразы без повторений слов (наиболее вероятные)
    unique_lines = [l for l in lines if len(set(l.split("|")[0].strip().split())) == 12]
    other_lines = [l for l in lines if len(set(l.split("|")[0].strip().split())) < 12]
    all_sorted = unique_lines + other_lines
    print(f"  • С уникальными 12 словами: {len(unique_lines)}")
    print(f"  • С повторениями: {len(other_lines)}")

    count = 0
    for l in all_sorted:
        res = check_phrase_passphrases(l)
        count += 1
        if count % 1000 == 0:
            print(f"  Проверено {count} / {len(all_sorted)} мнемоник...")
        if res:
            p, pw, path, comp, meta = res
            print("\n" + "!" * 75)
            print("🎉 УРА! НАЙДЕНА СИД-ФРАЗА И ПАРОЛЬ!")
            print(f"Адрес: {TARGET_ADDRESS}")
            print(f"Фраза: {p}")
            print(f"Пароль: '{pw}'")
            print(f"Путь деривации: {path} (compressed={comp})")
            print(f"Мета: {meta}")
            print("!" * 75)
            return

    elapsed = time.time() - start_time
    print("\n" + "=" * 75)
    print(f"Проверка завершена за {elapsed:.2f} сек. Проверено {count} мнемоник со всеми {len(PASSPHRASES)} паролями.")
    print("Совпадений с данным списком паролей не обнаружено.")
    print("=" * 75)

if __name__ == "__main__":
    main()
