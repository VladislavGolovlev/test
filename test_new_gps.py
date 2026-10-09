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
CANDIDATES_FILE = BASE_DIR / "valid_gps_candidates.txt"
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
    start_time = time.time()
    print("=" * 75)
    print("ТЕСТИРОВАНИЕ УТОЧНЁННЫХ GPS-КООРДИНАТ (WIKIPEDIA / OSM / LATLONG)")
    print("=" * 75)

    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        wordlist = [line.strip().lower() for line in f if line.strip()]
    word_to_idx = {w: i for i, w in enumerate(wordlist)}

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_content = f.read()

    sec1_raw = full_content.split("Fiat")[0]
    hdr_part, story_part = sec1_raw.split("Revolution", 1)
    header = "\n".join([l.strip() for l in hdr_part.splitlines() if "Press enter" not in l and l.strip()])
    story = "\n".join([l.strip() for l in story_part.splitlines() if "Press enter" not in l and l.strip()])

    layouts = [
        ("Режим 1: Чистый рассказ (без заголовка)", story),
        ("Режим 1B: Рассказ со словом Revolution", "Revolution\n" + story),
        ("Режим 2: Заголовок статьи + рассказ", header + "\n" + story),
        ("Режим 2B: Заголовок статьи + Revolution + рассказ", header + "\nRevolution\n" + story),
        ("Режим 3: Полный текст статьи", full_content),
    ]

    # База уточнённых и проверенных по гео-базам координат
    verified_locations = [
        # 1. Циндао (Qingdao)
        ("Циндао Мэрия (Wikipedia)", "360669", "120383"),
        ("Циндао Мэрия v2 (Wikipedia 120.3827)", "360669", "120382"),
        ("Циндао LatLong/Google", "360671", "120383"),
        ("Циндао Порт Даган (Dagang Old Port)", "360936", "120317"),
        ("Циндао Порт Даган v2", "360936", "120316"),
        ("Циндао Порт общий", "360566", "120320"),
        ("Циндао Пирс Чжаньцяо (Zhanqiao Pier)", "360600", "120315"),
        ("Циндао Пирс Чжаньцяо v2", "360617", "120314"),
        ("Циндао Пирс Чжаньцяо v3", "360583", "120313"),
        ("Циндао Вокзал (Railway Station 1901)", "360642", "120308"),
        ("Циндао Вокзал v2", "360634", "120311"),
        ("Циндао Бадагуань (Badaguan 1930s villas)", "360578", "120352"),
        
        # 2. Тайвань (Taiwan - Keelung & Taipei)
        ("Порт Цзилун (Keelung Port Wikipedia)", "251311", "121743"),
        ("Порт Цзилун v2 (121.7431)", "251311", "121744"),
        ("Порт Цзилун Harbor Mapcarta", "251405", "121750"),
        ("Город Цзилун (Keelung City Wikipedia)", "251333", "121733"),
        ("Город Цзилун v2 (25.1300, 121.7400)", "251300", "121740"),
        ("Тайбэй Мэрия (Taipei City Hall Wikipedia)", "250375", "121564"),
        ("Тайбэй OSM (Taipei OSM)", "250375", "121527"),
        ("Тайбэй Центр LatLong", "250330", "121565"),
        ("Тайбэй Центр v2", "250478", "121532"),
        ("Тайбэй Центр v3", "250531", "121526"),

        # 3. Оксфорд (Oxford - Jesus College & Bodleian)
        ("Оксфорд Jesus College (Wikipedia 51.7534, 1.2569)", "517534", "012569"),
        ("Оксфорд Jesus College v2 (51.7533, 01.2569)", "517533", "012569"),
        ("Оксфорд Jesus College v3 (без ведущего 0: 125694)", "517534", "125694"),
        ("Оксфорд Jesus College v4 (125690)", "517534", "125690"),
        ("Оксфорд Bodleian Library (Wikipedia 51.7539, 1.2544)", "517539", "012544"),
        ("Оксфорд Bodleian Library v2 (51.7537, 01.2541)", "517537", "012541"),
        ("Оксфорд Bodleian Library v3 (без 0)", "517539", "125444"),
        ("Оксфорд Radcliffe Camera", "517533", "012539"),

        # 4. Маунт-Вернон (Mount Vernon, Virginia)
        ("Маунт-Вернон Mansion (Wikipedia 38.7081, 77.0861)", "387081", "770861"),
        ("Маунт-Вернон Mansion v2 (38.7080, 77.0861)", "387080", "770861"),
        ("Маунт-Вернон CDP (Wikipedia 38.7353, 77.0953)", "387353", "770953"),

        # 5. Иоганн Тритемий (Trithemius locations)
        ("Триттенхайм (Trittenheim Wikipedia 49.8258, 6.9006)", "498258", "069006"),
        ("Триттенхайм v2 (без ведущего 0: 690056)", "498258", "690056"),
        ("Триттенхайм v3 (старый мост)", "498242", "069011"),
        ("Шпонхайм Аббатство (Kloster Sponheim 49.8457, 7.7250)", "498457", "077250"),
        ("Шпонхайм Деревня (Sponheim Wikipedia 49.8458, 7.7264)", "498458", "077264"),
        ("Шпонхайм Замок (Burg Sponheim 49.8317, 7.7147)", "498317", "077147"),
        ("Вюрцбург Schottenkloster (St. James 49.7956, 9.9206)", "497956", "099206"),
        ("Вюрцбург Schottenkloster v2 (49.7953, 09.9206)", "497953", "099206"),
        ("Вюрцбург Schottenkloster без 0", "497953", "992056"),
        ("Вюрцбург Центр города (Wikipedia 49.7931, 9.9383)", "497931", "099383"),

        # 6. Цинь (Qin Dynasty)
        ("Цинь Сяньян Дворец (Palace 34.4158, 108.8626)", "344158", "108863"),
        ("Цинь Сяньян Дворец v2 (34.4067, 108.8247)", "344067", "108825"),
        ("Цинь Сяньян Руины города (34.4139, 108.8578)", "344139", "108858"),
        ("Цинь Сяньян Мэрия (34.3299, 108.7088)", "343299", "108709"),
        ("Цинь Сяньян Мэрия v2 (34.3300, 108.7089)", "343300", "108709"),
        ("Цинь Мавзолей Цинь Шихуана (34.3817, 109.2539)", "343817", "109254"),
        ("Цинь Мавзолей Цинь Шихуана v2 (34.3814, 109.2536)", "343814", "109254"),
        ("Цинь Сиань Колокольня (Bell Tower 34.2610, 108.9423)", "342610", "108942"),
        ("Цинь Сиань Центр (Xi'an Wikipedia 34.2611, 108.9422)", "342611", "108942"),

        # 7. Эталон (Supreme Court)
        ("Верховный суд США (Supreme Court)", "388906", "770044"),
    ]

    print(f"Загружено локаций и вариантов: {len(verified_locations)}")

    total_tested = 0
    valid_candidates = []

    def test_phrase(words_12, desc):
        nonlocal total_tested
        total_tested += 1
        if not verify_bip39_checksum(words_12, word_to_idx):
            return False
        
        mnemonic = " ".join(words_12)
        valid_candidates.append(f"{mnemonic} | {desc}")
        
        # Проверяем сид
        for pass_opt in ["", "mnemonic", "Trithemius", "trithemius"]:
            seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), f"mnemonic{pass_opt}".encode("utf-8"), 2048)
            for path in DERIVATION_PATHS:
                for comp in [True, False]:
                    addr = derive_address(seed, path, compressed=comp)
                    if addr == TARGET_ADDRESS:
                        print("\n" + "!" * 75)
                        print("🎉 УРА! ЦЕЛЕВОЙ КОШЕЛЕК НАЙДЕН!")
                        print(f"Адрес: {addr}")
                        print(f"Фраза: {mnemonic}")
                        print(f"Пароль: '{pass_opt}'")
                        print(f"Путь: {path} (compressed={comp})")
                        print(f"Описание алгоритма: {desc}")
                        print("!" * 75)
                        return True
        return False

    for layout_name, layout_text in layouts:
        print(f"\n--- Тестируем {layout_name} ---")
        for tok_name, tokenizer in [("Пробельная", tokenize_whitespace), ("Регулярная", tokenize_regex)]:
            words_all = tokenizer(layout_text)
            words_bip = [w.lower() for w in words_all if w.lower() in word_to_idx]
            len_all = len(words_all)
            len_bip = len(words_bip)

            for loc_name, lat, lon in verified_locations:
                for digits_str in [lat + lon, lon + lat]:
                    digits = [int(c) for c in digits_str if c.isdigit()]
                    if len(digits) < 12:
                        digits = (digits * 2)[:12]
                    else:
                        digits = digits[:12]

                    # 1. Формула автора: index[i] = digit[i] + 10 * i
                    for step in [10, 9, 11, 8, 12]:
                        for start_mult in [0, 1]:
                            for offset in range(-3, 4):
                                # По всем словам (линейно без переполнения)
                                idx_lin = [digits[i] + step * (i + start_mult) + offset for i in range(12)]
                                if all(0 <= idx < len_all for idx in idx_lin):
                                    w_cand = [words_all[idx] for idx in idx_lin]
                                    if all(w.lower() in word_to_idx for w in w_cand):
                                        if test_phrase(w_cand, f"{layout_name} ({tok_name}) | Линейно все слова, {loc_name}, s={step}, m={start_mult}, off={offset}"):
                                            return

                                # По всем словам (по модулю)
                                idx_mod = [(digits[i] + step * (i + start_mult) + offset) % len_all for i in range(12)]
                                w_cand_mod = [words_all[idx] for idx in idx_mod]
                                if all(w.lower() in word_to_idx for w in w_cand_mod):
                                    if test_phrase(w_cand_mod, f"{layout_name} ({tok_name}) | Mod все слова, {loc_name}, s={step}, m={start_mult}, off={offset}"):
                                        return

                                # По отфильтрованным BIP-39 словам (линейно)
                                if all(0 <= idx < len_bip for idx in idx_lin):
                                    w_bip_lin = [words_bip[idx] for idx in idx_lin]
                                    if test_phrase(w_bip_lin, f"{layout_name} ({tok_name}) | Линейно BIP слова, {loc_name}, s={step}, m={start_mult}, off={offset}"):
                                        return

                                # По отфильтрованным BIP-39 словам (по модулю)
                                idx_bip_mod = [(digits[i] + step * (i + start_mult) + offset) % len_bip for i in range(12)]
                                w_bip_mod = [words_bip[idx] for idx in idx_bip_mod]
                                if test_phrase(w_bip_mod, f"{layout_name} ({tok_name}) | Mod BIP слова, {loc_name}, s={step}, m={start_mult}, off={offset}"):
                                    return

                    # 2. Масштабированные шаги (для длинного рассказа ~584 слова)
                    # Если рассказ длиннее 114 слов, шаг может быть пропорционален: ~45-50
                    for scale_step in [40, 45, 48, 50]:
                        for offset in range(-2, 3):
                            idx_scale = [(digits[i] + scale_step * i + offset) % len_all for i in range(12)]
                            w_scale = [words_all[idx] for idx in idx_scale]
                            if all(w.lower() in word_to_idx for w in w_scale):
                                if test_phrase(w_scale, f"{layout_name} ({tok_name}) | Scaled step={scale_step}, {loc_name}, off={offset}"):
                                    return

    elapsed = time.time() - start_time
    print("\n" + "=" * 75)
    print(f"Завершено за {elapsed:.2f} сек.")
    print(f"Всего проверено комбинаций: {total_tested}")
    print(f"Найдено математически валидных BIP-39 мнемоник: {len(valid_candidates)}")
    
    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        for c in valid_candidates:
            f.write(c + "\n")
    print(f"Кандидаты сохранены в: {CANDIDATES_FILE}")
    print(f"Целевой адрес: {TARGET_ADDRESS}")
    print("=" * 75)

if __name__ == "__main__":
    main()
