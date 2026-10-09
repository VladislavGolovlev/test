import hashlib
import hmac
import itertools
import re
import sys
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import coincurve
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
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]

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

def check_seed_fast(seed: bytes) -> tuple | None:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]
    
    # 1. m/44'/0'/0'/0/0
    # m/44'
    k44, c44 = ckd_priv(master_k, master_c, 44 + 0x80000000)
    # m/44'/0'
    k44_0, c44_0 = ckd_priv(k44, c44, 0 + 0x80000000)
    # m/44'/0'/0'
    k44_0_0, c44_0_0 = ckd_priv(k44_0, c44_0, 0 + 0x80000000)
    # m/44'/0'/0'/0
    k44_0_0_0, c44_0_0_0 = ckd_priv(k44_0_0, c44_0_0, 0)
    # m/44'/0'/0'/0/0
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

# Загрузка словаря
with open(WORDS_FILE, "r", encoding="utf-8") as f:
    wordlist = [w.strip().lower() for w in f if w.strip()]
word_to_idx = {w: i for i, w in enumerate(wordlist)}
bip_set = set(wordlist)

# Список координат
LOCATIONS = [
    # 1. Циндао (Qingdao)
    ("Циндао Мэрия", "360669", "120383"),
    ("Циндао Мэрия v2", "360669", "120382"),
    ("Циндао Мэрия drop100", "360669", "203827"),
    ("Циндао Порт Даган", "360936", "120317"),
    ("Циндао Порт Даган drop100", "360936", "203167"),
    ("Циндао Порт общий", "360566", "120320"),
    ("Циндао Пирс Чжаньцяо", "360600", "120315"),
    ("Циндао Пирс Чжаньцяо drop100", "360600", "203148"),
    ("Циндао Вокзал 1901", "360642", "120308"),
    ("Циндао Вокзал drop100", "360642", "203083"),
    ("Циндао Бадагуань", "360578", "120352"),
    
    # 2. Тайвань (Taiwan - Keelung & Taipei)
    ("Порт Цзилун", "251311", "121743"),
    ("Порт Цзилун drop100", "251311", "217431"),
    ("Город Цзилун", "251333", "121733"),
    ("Тайбэй Мэрия", "250375", "121564"),
    ("Тайбэй LatLong", "250330", "121565"),
    ("Тайбэй Main Station", "250478", "121517"),

    # 3. Оксфорд (Oxford)
    ("Оксфорд Jesus College (012569)", "517534", "012569"),
    ("Оксфорд Jesus College (125690)", "517534", "125690"),
    ("Оксфорд Bodleian (012544)", "517539", "012544"),
    ("Оксфорд Bodleian (125440)", "517539", "125440"),

    # 4. Маунт-Вернон (Mount Vernon)
    ("Маунт-Вернон Mansion", "387081", "770861"),
    ("Маунт-Вернон CDP", "387353", "770953"),

    # 5. Тритемий
    ("Триттенхайм (069006)", "498258", "069006"),
    ("Триттенхайм (690056)", "498258", "690056"),
    ("Шпонхайм Аббатство (077250)", "498457", "077250"),
    ("Шпонхайм Деревня (077264)", "498458", "077264"),
    ("Вюрцбург Schottenkloster (099206)", "497956", "099206"),
    ("Вюрцбург (992056)", "497956", "992056"),

    # 6. Цинь (Qin Dynasty)
    ("Цинь Сяньян Дворец", "344158", "108863"),
    ("Цинь Сяньян Руины", "344139", "108858"),
    ("Цинь Сяньян Мэрия", "343300", "108709"),
    ("Цинь Мавзолей Шихуана", "343817", "109254"),
    ("Цинь Сиань Колокольня", "342610", "108942"),

    # 7. Верховный суд США (контрольный)
    ("Верховный суд США", "388906", "770044"),
]

def run_tests():
    t0 = time.time()
    print("=" * 75, flush=True)
    print("ВЫСОКОСКОРОСТНОЙ ПОИСК PROXIMITY GPS С ПОДДЕРЖКОЙ COINCURVE (libsecp256k1)", flush=True)
    print(f"Целевой адрес: {TARGET_ADDRESS}", flush=True)
    print("=" * 75, flush=True)

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    sec1 = full_text.split("Fiat")[0].split("Revolution")[1].strip()
    sec1_with_rev = "Revolution\n" + sec1
    sec1_with_hdr = full_text.split("Fiat")[0].strip()
    
    idx_time = sec1.find("changing time")
    sec1_from_time = sec1[idx_time:] if idx_time != -1 else sec1

    layouts = [
        ("Чистый рассказ", sec1),
        ("С Revolution", sec1_with_rev),
        ("С заголовком", sec1_with_hdr),
        ("От слова TIME", sec1_from_time),
        ("Полный текст", full_text),
    ]

    total_candidates_tested = 0
    valid_checksums = 0

    # -------------------------------------------------------------
    # ЭКСПЕРИМЕНТ 1: Индексация по отфильтрованным BIP-39 словам
    # (в Section 1 ровно ~112-118 BIP-слов, диапазон формулы 0..119)
    # -------------------------------------------------------------
    print("\n[ЭКСПЕРИМЕНТ 1]: Proximity-поиск по списку BIP-39 слов рассказа (словарь 112-118 слов)", flush=True)
    for l_name, l_text in layouts:
        tokens = [re.sub(r"^[^\w]+|[^\w]+$", "", w).lower() for w in l_text.split()]
        bip_words = [w for w in tokens if w in bip_set]
        bip_idxs = [word_to_idx[w] for w in bip_words]
        n_bip = len(bip_words)
        print(f"  Раскладка '{l_name}': BIP-39 слов = {n_bip}", flush=True)

        for loc_name, lat, lon in LOCATIONS:
            for d_str in [lat + lon, lon + lat]:
                digits = [int(c) for c in d_str if c.isdigit()][:12]
                if len(digits) < 12:
                    continue

                for step in [10, 9, 11]:
                    for start_mult in [0, 1]:
                        # Погрешность delta in {-1, 0, 1} для каждой цифры
                        # Проверяем для смещений +-1 по каждой позиции
                        # Для предотвращения взрыва комбинаций (3^12 = 531k):
                        # Сначала проверяем точные позиции (delta=0)
                        # Затем единичные и двойные отклонения, либо декартово произведение по +-1
                        
                        # Шаг 1: Проверяем варианты с единым смещением delta in [-3..3]
                        for g_off in range(-3, 4):
                            t_idxs = []
                            for i in range(12):
                                p = digits[i] + step * (i + start_mult) + g_off
                                if p < 0 or p >= n_bip:
                                    break
                                t_idxs.append(bip_idxs[p])
                            if len(t_idxs) == 12:
                                total_candidates_tested += 1
                                if verify_checksum(t_idxs):
                                    valid_checksums += 1
                                    phrase = " ".join([bip_words[digits[i] + step * (i + start_mult) + g_off] for i in range(12)])
                                    for pw in PASSPHRASES:
                                        salt = ("mnemonic" + pw).encode("utf-8")
                                        seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
                                        match = check_seed_fast(seed)
                                        if match:
                                            path, comp = match
                                            print("\n" + "!" * 75, flush=True)
                                            print("🎉 УРА! НАЙДЕН МАТЧ В BIP-СПИСКЕ!", flush=True)
                                            print(f"Фраза: {phrase}", flush=True)
                                            print(f"Пароль: '{pw}'", flush=True)
                                            print(f"Путь: {path} (comp={comp})", flush=True)
                                            print(f"Локация: {loc_name}, g_off={g_off}", flush=True)
                                            print("!" * 75, flush=True)
                                            return

                        # Шаг 2: Независимый поиск для каждой позиции с окном +-1
                        # 3 варианта на позицию: T_i - 1, T_i, T_i + 1
                        slot_options = []
                        valid_slots = True
                        for i in range(12):
                            base_p = digits[i] + step * (i + start_mult)
                            opts = []
                            for delta in (-1, 0, 1):
                                p = base_p + delta
                                if 0 <= p < n_bip:
                                    opts.append(p)
                            if not opts:
                                valid_slots = False
                                break
                            slot_options.append(opts)

                        if not valid_slots:
                            continue

                        # Тестируем декартово произведение слотов
                        # 3^12 = 531,441 — фильтруем по чексумме
                        for prod in itertools.product(*slot_options):
                            cand_idxs = [bip_idxs[p] for p in prod]
                            total_candidates_tested += 1
                            if verify_checksum(cand_idxs):
                                valid_checksums += 1
                                phrase = " ".join([bip_words[p] for p in prod])
                                for pw in PASSPHRASES:
                                    salt = ("mnemonic" + pw).encode("utf-8")
                                    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
                                    match = check_seed_fast(seed)
                                    if match:
                                        path, comp = match
                                        print("\n" + "!" * 75, flush=True)
                                        print("🎉 УРА! НАЙДЕН МАТЧ В ПОЛНОМ PROXIMITY ПОИСКЕ!", flush=True)
                                        print(f"Фраза: {phrase}", flush=True)
                                        print(f"Пароль: '{pw}'", flush=True)
                                        print(f"Путь: {path} (comp={comp})", flush=True)
                                        print(f"Локация: {loc_name}", flush=True)
                                        print("!" * 75, flush=True)
                                        return

    print(f"\n[ЭКСПЕРИМЕНТ 1 завершен] Проверено кандидатов: {total_candidates_tested}, валидных чексумм: {valid_checksums}", flush=True)
    print(f"Затрачено времени: {time.time() - t0:.2f} сек.", flush=True)

if __name__ == "__main__":
    run_tests()
