import hashlib
import hmac
import re
import sys
import time
from pathlib import Path
import ecdsa
import base58

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = Path(r"c:\Users\Vladislav\Desktop\Новая папка")
TEXT_FILE = BASE_DIR / "clean_article.txt"
WORDS_FILE = BASE_DIR / "word.txt"
TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"

DERIVATION_PATHS = [
    "m/44'/0'/0'/0/0",
    "m/44'/0'/0'/0/1",
    "m/44'/0'/0'/0/2",
    "m/0'/0'/0'",
    "m/0/0",
    "m/44'/0'/0'/0",
    "m/44'/0'/0'",
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

def verify_bip39_checksum(words: list[str], word_to_idx: dict[str, int]) -> bool:
    if len(words) != 12:
        return False
    idxs = [word_to_idx.get(w.lower()) for w in words]
    if any(i is None for i in idxs):
        return False
    val = 0
    for idx in idxs:
        val = (val << 11) | idx
    entropy = (val >> 4).to_bytes(16, "big")
    expected_cs = hashlib.sha256(entropy).digest()[0] >> 4
    actual_cs = val & 0x0F
    return actual_cs == expected_cs

def tokenize_whitespace(text: str) -> list[str]:
    raw_tokens = text.split()
    tokens = []
    for t in raw_tokens:
        cleaned = re.sub(r"^[^\w]+|[^\w]+$", "", t).strip()
        if cleaned:
            tokens.append(cleaned)
    return tokens

def tokenize_regex(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z]+", text)

def main():
    print("=" * 75)
    print("ТЕСТИРОВАНИЕ GPS-КООРДИНАТ ПО КОНКРЕТНЫМ АБЗАЦАМ ИСТОРИИ")
    print("=" * 75)

    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        wordlist = [line.strip().lower() for line in f if line.strip()]
    word_to_idx = {w: i for i, w in enumerate(wordlist)}

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_content = f.read()

    sec1_raw = full_content.split("Fiat")[0]
    hdr_part, story_part = sec1_raw.split("Revolution", 1)
    story_clean = "\n".join([l.strip() for l in story_part.splitlines() if "Press enter" not in l and l.strip()])

    paragraphs = [p.strip() for p in story_part.replace("\r\n", "\n").split("\n\n") if p.strip() and "Press enter" not in p]
    print(f"Выделено абзацев в рассказе: {len(paragraphs)}")

    test_blocks = []
    for i, p in enumerate(paragraphs, 1):
        test_blocks.append((f"Абзац {i}", p))
    # Пары и тройки абзацев
    for i in range(len(paragraphs) - 1):
        test_blocks.append((f"Абзацы {i+1}+{i+2}", paragraphs[i] + "\n" + paragraphs[i+1]))
    # Блок Циндао (P7 + P8 + P9)
    test_blocks.append(("Блок Циндао (P7+P8+P9)", "\n".join(paragraphs[6:9])))

    # Выверенная база координат
    locations = [
        # Циндао
        ("Циндао Пирс Чжаньцяо (Zhanqiao)", "360600", "120315"),
        ("Циндао Пирс Чжаньцяо drop100", "360600", "203148"),
        ("Циндао Порт Даган (Dagang)", "360936", "120317"),
        ("Циндао Порт Даган drop100", "360936", "203167"),
        ("Циндао Пассажирский вокзал", "360872", "120315"),
        ("Циндао Вокзал ж/д", "360642", "120308"),
        ("Циндао Мэрия", "360669", "120383"),
        # Тайвань
        ("Тайвань Порт Цзилун (Keelung)", "251311", "121743"),
        ("Тайвань Порт Цзилун drop100", "251311", "217431"),
        ("Тайвань Тайбэй City Hall", "250375", "121564"),
        ("Тайвань Тайбэй Main Station", "250478", "121517"),
        # Оксфорд
        ("Оксфорд Jesus College (012569)", "517533", "012569"),
        ("Оксфорд Jesus College (125690)", "517533", "125690"),
        ("Оксфорд Бодлиан (012544)", "517539", "012544"),
        # Маунт-Вернон
        ("Маунт-Вернон Особняк", "387081", "770861"),
        ("Маунт-Вернон OSM", "387079", "770861"),
        # Тритемий
        ("Триттенхайм (069006)", "498258", "069006"),
        ("Шпонхайм Аббатство (077250)", "498457", "077250"),
        ("Вюрцбург Schottenkloster (099206)", "497956", "099206"),
        # Цинь
        ("Цинь Сяньян Дворец", "344158", "108863"),
        ("Цинь Мавзолей Цинь Шихуана", "343817", "109254"),
        ("Цинь Сиань Колокольня", "342610", "108942"),
    ]

    total_valid = 0

    for block_name, block_text in test_blocks:
        for tok_name, tokenizer in [("Пробельная", tokenize_whitespace), ("Регулярная", tokenize_regex)]:
            words = tokenizer(block_text)
            len_w = len(words)
            if len_w < 12:
                continue

            for loc_name, lat, lon in locations:
                for digits_str in [lat + lon, lon + lat]:
                    digits = [int(c) for c in digits_str if c.isdigit()]
                    if len(digits) < 12:
                        continue
                    digits = digits[:12]

                    for step in [10, 9, 11, 8, 12]:
                        for start_mult in [0, 1]:
                            for offset in range(-2, 3):
                                # 1. 1-based (как у автора)
                                idx_1based = [digits[i] + step * (i + start_mult) + offset - 1 for i in range(12)]
                                if all(0 <= idx < len_w for idx in idx_1based):
                                    w_cand = [words[idx] for idx in idx_1based]
                                    if all(w.lower() in word_to_idx for w in w_cand):
                                        if verify_bip39_checksum(w_cand, word_to_idx):
                                            total_valid += 1
                                            mnemonic = " ".join(w_cand)
                                            print(f"\n[VALID BIP-39!] {block_name} ({tok_name}) | {loc_name} s={step} m={start_mult} off={offset}")
                                            print(f"  Фраза: {mnemonic}")
                                            # Проверяем кошелёк
                                            for p_opt in ["", "mnemonic", "Trithemius", "trithemius"]:
                                                seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), f"mnemonic{p_opt}".encode("utf-8"), 2048)
                                                for path in DERIVATION_PATHS:
                                                    for comp in [True, False]:
                                                        addr = derive_address(seed, path, compressed=comp)
                                                        if addr == TARGET_ADDRESS:
                                                            print("🎉 НАЙДЕН ЦЕЛЕВОЙ КОШЕЛЕК!")
                                                            return

                                # 2. 0-based
                                idx_0based = [digits[i] + step * (i + start_mult) + offset for i in range(12)]
                                if all(0 <= idx < len_w for idx in idx_0based):
                                    w_cand = [words[idx] for idx in idx_0based]
                                    if all(w.lower() in word_to_idx for w in w_cand):
                                        if verify_bip39_checksum(w_cand, word_to_idx):
                                            total_valid += 1
                                            mnemonic = " ".join(w_cand)
                                            print(f"\n[VALID BIP-39!] {block_name} ({tok_name}) | {loc_name} s={step} m={start_mult} off={offset} (0-based)")
                                            print(f"  Фраза: {mnemonic}")
                                            for p_opt in ["", "mnemonic", "Trithemius", "trithemius"]:
                                                seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), f"mnemonic{p_opt}".encode("utf-8"), 2048)
                                                for path in DERIVATION_PATHS:
                                                    for comp in [True, False]:
                                                        addr = derive_address(seed, path, compressed=comp)
                                                        if addr == TARGET_ADDRESS:
                                                            print("🎉 НАЙДЕН ЦЕЛЕВОЙ КОШЕЛЕК!")
                                                            return

    print("\n" + "=" * 75)
    print(f"Проверка завершена. Найдено валидных BIP-39 фраз: {total_valid}")
    print("=" * 75)

if __name__ == "__main__":
    main()
