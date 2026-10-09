import hashlib
import hmac
import itertools
import re
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
TEXT_FILE = BASE_DIR / "clean_article.txt"
WORDS_FILE = BASE_DIR / "word.txt"
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
    "time",
    "Time",
    "TIME",
    "changing time",
    "turbulent and changing time",
    "Trithemius",
    "Revolution",
    "Poetry",
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
    Il, Ir = I[:32], I[32:]
    parse_il = int.from_bytes(Il, "big")
    if parse_il >= SECP256K1_ORDER:
        return None, None
    k_i = (parse_il + int.from_bytes(parent_k, "big")) % SECP256K1_ORDER
    if k_i == 0:
        return None, None
    return k_i.to_bytes(32, "big"), Ir

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
        cleaned = re.sub(r"^[^\w]+|[^\w]+$", "", t).strip().lower()
        if cleaned:
            tokens.append(cleaned)
    return tokens

def tokenize_regex(text: str) -> list[str]:
    return [w.lower() for w in re.findall(r"[a-zA-Z]+", text)]

# База координат проверенных локаций
VERIFIED_LOCATIONS = [
    # Циндао
    ("Циндао Мэрия", "360669", "120383"),
    ("Циндао Мэрия v2", "360669", "120382"),
    ("Циндао Порт Даган", "360936", "120317"),
    ("Циндао Порт Даган v2", "360936", "120316"),
    ("Циндао Порт общий", "360566", "120320"),
    ("Циндао Пирс Чжаньцяо", "360600", "120315"),
    ("Циндао Пирс Чжаньцяо v2", "360617", "120314"),
    ("Циндао Вокзал 1901", "360642", "120308"),
    ("Циндао Бадагуань", "360578", "120352"),
    # Тайвань
    ("Порт Цзилун", "251311", "121743"),
    ("Порт Цзилун v2", "251311", "121744"),
    ("Город Цзилун", "251333", "121733"),
    ("Тайбэй Мэрия", "250375", "121564"),
    ("Тайбэй LatLong", "250330", "121565"),
    # Оксфорд
    ("Оксфорд Jesus College", "517534", "012569"),
    ("Оксфорд Jesus College (125690)", "517534", "125690"),
    ("Оксфорд Bodleian", "517539", "012544"),
    # Маунт-Вернон
    ("Маунт-Вернон Mansion", "387081", "770861"),
    ("Маунт-Вернон CDP", "387353", "770953"),
    # Тритемий
    ("Триттенхайм", "498258", "069006"),
    ("Шпонхайм Аббатство", "498457", "077250"),
    ("Шпонхайм Замок", "498317", "077147"),
    ("Вюрцбург Schottenkloster", "497956", "099206"),
    # Цинь
    ("Цинь Сяньян Дворец", "344158", "108863"),
    ("Цинь Сяньян Руины", "344139", "108858"),
    ("Цинь Мавзолей Шихуана", "343817", "109254"),
    ("Цинь Сиань Колокольня", "342610", "108942"),
    # Верховный суд (контрольный)
    ("Верховный суд США", "388906", "770044"),
]

def find_candidate_words_near(target_pos: int, words: list[str], bip_set: set[str], radius: int = 3, max_per_pos: int = 2) -> list[str]:
    """Находит ближайшие BIP-39 слова в окне [target_pos - radius, target_pos + radius]."""
    candidates = []
    # Сначала проверяем точную позицию
    for dist in range(radius + 1):
        for offset in ([0] if dist == 0 else [offset for offset in [-dist, dist]]):
            p = target_pos + offset
            if 0 <= p < len(words):
                w = words[p]
                if w in bip_set and w not in candidates:
                    candidates.append(w)
                    if len(candidates) >= max_per_pos:
                        return candidates
    return candidates

def test_single_mnemonic(phrase: str):
    """Проверка мнемоники по всем путям и паролям."""
    words = phrase.split()
    for pw in PASSPHRASES:
        salt = ("mnemonic" + pw).encode("utf-8")
        seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
        for path in DERIVATION_PATHS:
            for comp in [True, False]:
                addr = derive_address(seed, path, compressed=comp)
                if addr == TARGET_ADDRESS:
                    return phrase, pw, path, comp
    return None

def main():
    t0 = time.time()
    print("=" * 75)
    print("МОДЕРНИЗИРОВАННЫЙ GPS МЕТОД: PROXIMITY / NEIGHBORHOOD ПОИСК")
    print(f"Целевой адрес: {TARGET_ADDRESS}")
    print("=" * 75)

    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        wordlist = [w.strip().lower() for w in f if w.strip()]
    word_to_idx = {w: i for i, w in enumerate(wordlist)}
    bip_set = set(wordlist)

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_content = f.read()

    sec1_raw = full_content.split("Fiat")[0]
    hdr_part, story_part = sec1_raw.split("Revolution", 1)
    story = "\n".join([l.strip() for l in story_part.splitlines() if l.strip()])
    
    # Находим позицию выделенного слова "time" во 2-м абзаце
    # "...quietly turbulent and changing time. He was the eldest..."
    time_split_idx = story.find("changing time")
    story_from_time = story[time_split_idx:] if time_split_idx != -1 else story

    layouts = [
        ("Чистый рассказ (Story)", story),
        ("С заголовком Revolution", "Revolution\n" + story),
        ("От выделенного слова TIME во 2-м абзаце", story_from_time),
        ("Полный текст статьи", full_content),
    ]

    total_phrases_checked = 0
    valid_checksums_found = 0
    match_found = False

    for layout_name, layout_text in layouts:
        print(f"\n>>> РАСКЛАДКА: {layout_name}")
        for tok_name, tokenizer in [("Пробельная", tokenize_whitespace), ("Регулярная", tokenize_regex)]:
            tokens = tokenizer(layout_text)
            n_tokens = len(tokens)
            print(f"  [{tok_name}] Слов в тексте: {n_tokens}")

            for loc_name, lat, lon in VERIFIED_LOCATIONS:
                for digits_str in [lat + lon, lon + lat]:
                    digits = [int(c) for c in digits_str if c.isdigit()][:12]
                    if len(digits) < 12:
                        continue

                    # Проверяем несколько шагов: классический step=10, 1-based (i=0..11, step*i) и (step*(i+1))
                    for step in [10, 9, 11]:
                        for start_mult in [0, 1]:
                            for radius in [1, 2, 3]:
                                # Формируем список кандидатов для каждой из 12 позиций
                                pos_candidates = []
                                valid_all_12 = True
                                for i in range(12):
                                    base_idx = digits[i] + step * (i + start_mult)
                                    # 1-based to 0-based index
                                    idx_0 = base_idx - 1
                                    cands = find_candidate_words_near(idx_0, tokens, bip_set, radius=radius, max_per_pos=2)
                                    if not cands:
                                        valid_all_12 = False
                                        break
                                    pos_candidates.append(cands)

                                if not valid_all_12:
                                    continue

                                # Декартово произведение кандидатов
                                # Если комбинаций не слишком много (например <= 4096)
                                combinations_count = 1
                                for c in pos_candidates:
                                    combinations_count *= len(c)

                                if combinations_count > 4096:
                                    # Берем только по 1 ближайшему если слишком много
                                    pos_candidates = [c[:1] for c in pos_candidates]
                                    combinations_count = 1

                                for word_tuple in itertools.product(*pos_candidates):
                                    words_12 = list(word_tuple)
                                    total_phrases_checked += 1
                                    if verify_bip39_checksum(words_12, word_to_idx):
                                        valid_checksums_found += 1
                                        phrase = " ".join(words_12)
                                        res = test_single_mnemonic(phrase)
                                        if res:
                                            p, pw, path, comp = res
                                            print("\n" + "!" * 75)
                                            print("🎉 УРА! НАЙДЕН ЦЕЛЕВОЙ КОШЕЛЕК!")
                                            print(f"Фраза: {p}")
                                            print(f"Пароль: '{pw}'")
                                            print(f"Путь: {path} (comp={comp})")
                                            print(f"Локация: {loc_name}, step={step}, r={radius}, mult={start_mult}")
                                            print("!" * 75)
                                            match_found = True
                                            return

    elapsed = time.time() - t0
    print("\n" + "=" * 75)
    print(f"Поиск завершен за {elapsed:.2f} сек.")
    print(f"Всего сформировано и проверено комбинаций: {total_phrases_checked}")
    print(f"Валидных по контрольной сумме BIP-39 фраз: {valid_checksums_found}")
    if not match_found:
        print("Совпадений с целевым адресом при радиусе r<=3 не найдено.")
    print("=" * 75)

if __name__ == "__main__":
    main()
