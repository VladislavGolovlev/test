import hashlib
import hmac
import itertools
import sys
import time
from pathlib import Path
import coincurve
import base58

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = Path(r"c:\Users\Vladislav\Desktop\Новая папка")
WORDS_FILE = BASE_DIR / "word.txt"
TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]

PASSPHRASES = [
    "",
    "time",
    "Time",
    "TIME",
    "changing time",
    "turbulent and changing time",
    "Trithemius",
    "Revolution",
    "Poetry",
    "ye-ye",
    "1949",
    "gold",
]

SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

def ckd_priv(parent_k: bytes, parent_c: bytes, index: int):
    is_hardened = index >= 0x80000000
    if is_hardened:
        data = b"\x00" + parent_k + index.to_bytes(4, "big")
    else:
        pub = coincurve.PrivateKey(parent_k).public_key.format(compressed=True)
        data = pub + index.to_bytes(4, "big")
    I = hmac.new(parent_c, data, hashlib.sha512).digest()
    Il, Ir = I[:32], I[32:]
    parse_il = int.from_bytes(Il, "big")
    if parse_il >= SECP256K1_ORDER:
        return None, None
    k_i = (parse_il + int.from_bytes(parent_k, "big")) % SECP256K1_ORDER
    if k_i == 0:
        return None, None
    return k_i.to_bytes(32, "big"), Ir

def check_seed_fast(seed: bytes):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]
    
    # 1. m/44'/0'/0'/0/0
    k44, c44 = ckd_priv(master_k, master_c, 44 + 0x80000000)
    k44_0, c44_0 = ckd_priv(k44, c44, 0 + 0x80000000)
    k44_0_0, c44_0_0 = ckd_priv(k44_0, c44_0, 0 + 0x80000000)
    k44_0_0_0, c44_0_0_0 = ckd_priv(k44_0_0, c44_0_0, 0)
    k_addr0, _ = ckd_priv(k44_0_0_0, c44_0_0_0, 0)
    for comp in (True, False):
        pub = coincurve.PrivateKey(k_addr0).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m/44'/0'/0'/0/0", comp

    # m/44'/0'/0'/0/1
    k_addr1, _ = ckd_priv(k44_0_0_0, c44_0_0_0, 1)
    for comp in (True, False):
        pub = coincurve.PrivateKey(k_addr1).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m/44'/0'/0'/0/1", comp

    # 2. m/0'/0'/0'
    k0, c0 = ckd_priv(master_k, master_c, 0 + 0x80000000)
    k0_0, c0_0 = ckd_priv(k0, c0, 0 + 0x80000000)
    k0_0_0, _ = ckd_priv(k0_0, c0_0, 0 + 0x80000000)
    for comp in (True, False):
        pub = coincurve.PrivateKey(k0_0_0).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m/0'/0'/0'", comp

    # 3. m/0/0
    km0, cm0 = ckd_priv(master_k, master_c, 0)
    km0_0, _ = ckd_priv(km0, cm0, 0)
    for comp in (True, False):
        pub = coincurve.PrivateKey(km0_0).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m/0/0", comp

    return None

def verify_checksum(idxs_12: list[int]) -> bool:
    val = 0
    for idx in idxs_12:
        val = (val << 11) | idx
    entropy = (val >> 4).to_bytes(16, "big")
    expected_cs = hashlib.sha256(entropy).digest()[0] >> 4
    return (val & 0x0F) == expected_cs

# Загружаем 20 BIP слов первых двух абзацев Revolution
WORDS_P1_P2 = [
    (10, "into"),
    (12, "large"),
    (16, "family"),
    (19, "early"),
    (21, "during"),
    (24, "time"),
    (28, "decade"),
    (35, "that"),
    (37, "over"),
    (47, "find"),
    (50, "among"),
    (54, "shift"),
    (57, "civil"),
    (63, "world"),
    (73, "what"),
    (89, "time"),  # Выделенное слово
    (95, "six"),
    (100, "mother"),
    (108, "father"),
    (115, "frequent"),
]

def main():
    t0 = time.time()
    print("=" * 75, flush=True)
    print("ТЕСТИРОВАНИЕ ВСЕХ КОМБИНАЦИЙ 12 ИЗ 20 BIP-39 СЛОВ ПЕРВЫХ ДВУХ АБЗАЦЕВ (P1+P2)", flush=True)
    print(f"Целевой адрес: {TARGET_ADDRESS}", flush=True)
    print(f"BIP-39 слова ({len(WORDS_P1_P2)} шт): {[w for _, w in WORDS_P1_P2]}", flush=True)
    print("=" * 75, flush=True)

    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        wordlist = [w.strip().lower() for w in f if w.strip()]
    word_to_idx = {w: i for i, w in enumerate(wordlist)}

    word_items = [(pos, w, word_to_idx[w]) for pos, w in WORDS_P1_P2]

    total_combs = 0
    valid_cs_count = 0
    
    # 1. Строго по порядку (монотонно возрастающие индексы)
    # C(20, 12) = 125,970
    print("\n[Этап 1] Монотонный порядок (C(20, 12) = 125,970 комбинаций)...", flush=True)
    for comb in itertools.combinations(word_items, 12):
        total_combs += 1
        idxs_12 = [c[2] for c in comb]
        if verify_checksum(idxs_12):
            valid_cs_count += 1
            words_12 = [c[1] for c in comb]
            phrase = " ".join(words_12)
            for pw in PASSPHRASES:
                salt = ("mnemonic" + pw).encode("utf-8")
                seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
                match = check_seed_fast(seed)
                if match:
                    path, comp = match
                    print("\n" + "!" * 75, flush=True)
                    print("🎉🎉🎉 УРА! ЦЕЛЕВОЙ КОШЕЛЕК НАЙДЕН!", flush=True)
                    print(f"Фраза: {phrase}", flush=True)
                    print(f"Пароль: '{pw}'", flush=True)
                    print(f"Путь: {path} (comp={comp})", flush=True)
                    print(f"Позиции слов: {[c[0] for c in comb]}", flush=True)
                    print("!" * 75, flush=True)
                    return

    print(f"Этап 1 завершен за {time.time() - t0:.2f} сек. Проверено комбинаций: {total_combs}, валидных чексумм: {valid_cs_count}", flush=True)

    # 2. Что если в комбинации ОБЯЗАТЕЛЬНО присутствует выделенное слово TIME (поз 89)?
    # Выделенное слово time на скриншоте!
    time_item = [c for c in word_items if c[0] == 89][0]
    other_items = [c for c in word_items if c[0] != 89]
    print("\n[Этап 2] Все комбинации, где обязательно есть выделенное 'time' (поз 89):", flush=True)
    # C(19, 11) = 75,582 (уже входит в этап 1, если порядок монотонный)
    print("  Все монотонные комбинации с 'time' уже проверены на этапе 1.")

    print("\nСовпадений в чистом монотонном выборе из первых двух абзацев не найдено.", flush=True)

if __name__ == "__main__":
    main()
