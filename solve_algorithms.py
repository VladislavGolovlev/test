import hashlib
import hmac
import re
import sys
import time
from pathlib import Path
import ecdsa
import base58

# Настройка UTF-8 для корректного вывода русского текста в консоли Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# =====================================================================
# Конфигурация и пути к файлам
# =====================================================================
BASE_DIR = Path(r"c:\Users\Vladislav\Desktop\Новая папка")
TEXT_FILE = BASE_DIR / "clean_article.txt"
FALLBACK_TEXT_FILE = BASE_DIR / "Текстовый документ (2).txt"
WORDS_FILE = BASE_DIR / "word.txt"
CANDIDATES_FILE = BASE_DIR / "valid_candidates.txt"
TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"

# Пути деривации для Legacy адресов биткоина (P2PKH, начинающихся с 1...)
DERIVATION_PATHS = [
    "m/44'/0'/0'/0/0",  # Стандарт BIP-44 (аккаунт 0, адрес 0)
    "m/44'/0'/0'/0/1",  # BIP-44 (адрес 1)
    "m/44'/0'/0'/0/2",  # BIP-44 (адрес 2)
    "m/0'/0'/0'",      # Старый стандарт BIP-32
    "m/0/0",           # Electrum / Coinomi legacy
    "m/44'/0'/0'/0",   # Альтернативный путь 1
    "m/44'/0'/0'",     # Альтернативный путь 2
    "m/0",             # Упрощённый путь
    "m",               # Мастер-ключ без суб-деривации
]

# Дополнительные кодовые фразы (BIP-39 passphrase), упоминаемые в контексте
PASSPHRASES = [
    "",             # Стандартная пустая фраза (по умолчанию для BIP-39)
    "Trithemius",   # Имя автора / псевдоним
    "Revolution",   # Название первой главы
    "Poetry",       # Ключевое слово статьи
]

SECP256K1_ORDER = ecdsa.curves.SECP256k1.order

# =====================================================================
# Криптографические функции
# =====================================================================
def get_pubkey(priv_bytes: bytes, compressed: bool = True) -> bytes:
    """Вычисление публичного ключа из приватного (сжатый или несжатый)."""
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if not compressed:
        return b"\x04" + vk.to_string()
    pub = vk.to_string()
    prefix = b"\x02" if pub[-1] % 2 == 0 else b"\x03"
    return prefix + pub[:32]

def ckd_priv(parent_k: bytes, parent_c: bytes, index: int):
    """Деривация дочернего приватного ключа по BIP-32."""
    is_hardened = index >= 0x80000000
    if is_hardened:
        data = b"\x00" + parent_k + index.to_bytes(4, "big")
    else:
        pub = get_pubkey(parent_k, compressed=True)
        data = pub + index.to_bytes(4, "big")
    I = hmac.new(parent_c, data, hashlib.sha512).digest()
    Il, Ir = I[:32], I[32:]
    k_child = (int.from_bytes(Il, "big") + int.from_bytes(parent_k, "big")) % SECP256K1_ORDER
    return k_child.to_bytes(32, "big"), Ir

def pubkey_to_address(pubkey: bytes) -> str:
    """Конвертация публичного ключа в Legacy биткоин-адрес (Base58Check P2PKH)."""
    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return base58.b58encode_check(b"\x00" + ripe).decode("utf-8")

def derive_address(seed: bytes, path: str, compressed: bool = True) -> str:
    """Деривация биткоин-адреса по заданному пути деривации."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    if path != "m":
        for step in path.split("/")[1:]:
            hardened = step.endswith("'") or step.endswith("h")
            idx = int(step[:-1]) + 0x80000000 if hardened else int(step)
            k, c = ckd_priv(k, c, idx)
    pub = get_pubkey(k, compressed=compressed)
    return pubkey_to_address(pub)

def is_valid_bip39(words: list[str], word_to_idx: dict[str, int]) -> bool:
    """Проверка контрольной суммы мнемоники BIP-39 (12 слов -> 4 бита чексуммы)."""
    if len(words) != 12:
        return False
    for w in words:
        if w not in word_to_idx:
            return False
    bits = "".join(f"{word_to_idx[w]:011b}" for w in words)
    ent_bytes = int(bits[:128], 2).to_bytes(16, "big")
    h = hashlib.sha256(ent_bytes).digest()
    return bits[128:] == f"{h[0]:08b}"[:4]

# =====================================================================
# Глобальные структуры для сбора кандидатов и статистики
# =====================================================================
all_valid_found = []
tested_mnemonics = set()
total_tested_combinations = 0

def check_phrase(mnemonic_words: list[str], source_desc: str, word_to_idx: dict[str, int]) -> bool:
    """
    Проверка фразы-кандидата:
    1. Проверка наличия всех 12 слов в официальном словаре BIP-39
    2. Проверка контрольной суммы (SHA-256 чексумма BIP-39)
    3. Деривация адресов по всем путям (сжатые/несжатые ключи, с passphrase и без)
    4. Сравнение с целевым адресом TARGET_ADDRESS
    """
    global total_tested_combinations
    total_tested_combinations += 1

    if len(mnemonic_words) != 12:
        return False

    clean_words = [w.lower() for w in mnemonic_words]
    for w in clean_words:
        if w not in word_to_idx:
            return False

    if not is_valid_bip39(clean_words, word_to_idx):
        return False

    mnemonic = " ".join(clean_words)
    entry = f"{mnemonic} | Источник: {source_desc}"

    if mnemonic not in tested_mnemonics:
        tested_mnemonics.add(mnemonic)
        all_valid_found.append(entry)
        print(f"[✓ ВАЛИДНЫЙ BIP-39 СИД]: {mnemonic}")
        print(f"    -> Описание: {source_desc}")

        # Проверяем для каждой парольной фразы (стандартная пустая + ключевые слова)
        for passphrase in PASSPHRASES:
            salt = ("mnemonic" + passphrase).encode("utf-8")
            seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048)
            for path in DERIVATION_PATHS:
                for comp in [True, False]:
                    addr = derive_address(seed, path, compressed=comp)
                    if addr == TARGET_ADDRESS:
                        pass_info = f" (Passphrase: '{passphrase}')" if passphrase else ""
                        print("\n" + "=" * 75)
                        print("🎉🎉🎉 ДЖЕКПОТ! НАЙДЕНА СИД-ФРАЗА КОШЕЛЬКА! 🎉🎉🎉")
                        print(f"Источник: {source_desc}")
                        print(f"Мнемоника: {mnemonic}{pass_info}")
                        print(f"Путь деривации: {path} (сжатый ключ: {comp})")
                        print(f"Адрес: {addr}")
                        print("=" * 75)
                        return True
    return False

# =====================================================================
# Токенизаторы текста
# =====================================================================
def tokenize_whitespace(text: str) -> list[str]:
    """
    Каноническая пробельная токенизация (whitespace tokens):
    Разбивает текст по пробелам и очищает граничные знаки препинания.
    Именно этот способ подтверждён на официальном примере статьи Trithemius
    (Supreme Court, где friend's и aren't считаются едиными словами).
    """
    raw_tokens = text.split()
    tokens = []
    for t in raw_tokens:
        cleaned = re.sub(r"^[^\w]+|[^\w]+$", "", t).strip()
        if cleaned:
            tokens.append(cleaned)
    return tokens

def tokenize_regex(text: str) -> list[str]:
    """
    Регулярная буквенная токенизация:
    Извлекает только непрерывные последовательности букв a-z.
    """
    return re.findall(r"[a-zA-Z]+", text)

# =====================================================================
# Извлечение заголовка и чистого рассказа
# =====================================================================
def extract_story_and_header(filepath: Path) -> tuple[str, str]:
    """
    Автоматическое извлечение и очистка текста первой истории:
    - Отсекает заголовок статьи Medium ("Securing Wealth in Poetry...")
    - Извлекает чистый рассказ дедушки строго между маркёрами 'Revolution' и 'Fiat'
    - Убирает служебные строки (например, 'Press enter...')
    - Поддерживает автоматический фоллбэк между clean_article.txt и Текстовый документ (2).txt
    """
    target_path = filepath
    if not target_path.exists():
        if FALLBACK_TEXT_FILE.exists():
            target_path = FALLBACK_TEXT_FILE
        else:
            raise FileNotFoundError(f"Файл {filepath} не найден!")

    with open(target_path, "r", encoding="utf-8") as f:
        content = f.read()

    header = ""
    story = ""

    if "Fiat" in content:
        # Полный текст статьи: отсекаем всё после заголовка Fiat
        sec1_raw = content.split("Fiat")[0]
        if "Revolution" in sec1_raw:
            hdr_part, story_part = sec1_raw.split("Revolution", 1)
            # Очищаем заголовок
            header_lines = [l.strip() for l in hdr_part.splitlines() if "Press enter" not in l and l.strip()]
            header = "\n".join(header_lines)
            # Очищаем чистый рассказ
            story_lines = [l.strip() for l in story_part.splitlines() if "Press enter" not in l and l.strip()]
            story = "\n".join(story_lines)
        else:
            story_lines = [l.strip() for l in sec1_raw.splitlines() if "Press enter" not in l and l.strip()]
            story = "\n".join(story_lines)
    else:
        # Файл содержит только рассказ дедушки (например, "Текстовый документ (2).txt")
        story_lines = [l.strip() for l in content.splitlines() if "Press enter" not in l and l.strip() and l.strip() != "Revolution"]
        story = "\n".join(story_lines)

        # Пытаемся получить заголовок статьи из clean_article.txt
        ca_path = target_path.parent / "clean_article.txt"
        if ca_path.exists():
            try:
                with open(ca_path, "r", encoding="utf-8") as f_ca:
                    ca_text = f_ca.read()
                if "Revolution" in ca_text:
                    hdr_part = ca_text.split("Revolution")[0]
                    header = "\n".join(l.strip() for l in hdr_part.splitlines() if "Press enter" not in l and l.strip())
            except Exception:
                pass

        if not header:
            header = "Securing Wealth in Poetry\nWhat if you could embed your net worth in a story?"

    return header, story

# =====================================================================
# Основная процедура анализа
# =====================================================================
def main():
    print(f"Запуск расширенного систематического анализа для целевого адреса: {TARGET_ADDRESS}")
    print("=" * 75)

    # 1. Загрузка BIP-39 словаря
    if not WORDS_FILE.exists():
        print(f"Ошибка: файл словаря не найден: {WORDS_FILE}")
        return

    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        bip_words = [line.strip().lower() for line in f if line.strip()]
    word_to_idx = {w: i for i, w in enumerate(bip_words)}
    print(f"✓ Загружен словарь BIP-39: {len(bip_words)} слов")

    # 2. Извлечение заголовка и чистого рассказа
    header, story = extract_story_and_header(TEXT_FILE)
    hdr_words = tokenize_whitespace(header)
    hdr_bip = [w.lower() for w in hdr_words if w.lower() in word_to_idx]
    story_words_ws = tokenize_whitespace(story)
    story_bip_ws = [w.lower() for w in story_words_ws if w.lower() in word_to_idx]
    story_words_rx = tokenize_regex(story)
    story_bip_rx = [w.lower() for w in story_words_rx if w.lower() in word_to_idx]

    print(f"✓ Заголовок статьи: отсечён автоматически ({len(hdr_words)} слов, из них {len(hdr_bip)} в словаре BIP-39)")
    print(f"✓ Чистый рассказ (между Revolution и Fiat):")
    print(f"    • Пробельная токенизация: {len(story_words_ws)} слов ({len(story_bip_ws)} в BIP-39)")
    print(f"    • Регулярная токенизация: {len(story_words_rx)} слов ({len(story_bip_rx)} в BIP-39)")
    print("-" * 75)

    # 3. Раскладки текста (Режим 1: чистый рассказ, Режим 2: с заголовком, и их варианты)
    layouts = [
        {
            "mode_id": "Режим 1",
            "name": "Режим 1: Чистый рассказ строго между 'Revolution' и 'Fiat' (без заголовка статьи)",
            "text": story,
            "desc": "чистый рассказ без заголовка статьи"
        },
        {
            "mode_id": "Режим 1B",
            "name": "Режим 1B: Чистый рассказ с включением заголовка раздела 'Revolution'",
            "text": "Revolution\n" + story,
            "desc": "рассказ с заголовком раздела Revolution"
        },
        {
            "mode_id": "Режим 2",
            "name": "Режим 2: С учётом заголовка статьи (без слова 'Revolution')",
            "text": header + "\n" + story,
            "desc": "заголовок статьи + чистый рассказ"
        },
        {
            "mode_id": "Режим 2B",
            "name": "Режим 2B: С полным заголовком статьи и словом 'Revolution'",
            "text": header + "\nRevolution\n" + story,
            "desc": "заголовок статьи + Revolution + рассказ"
        },
        {
            "mode_id": "Режим 2C",
            "name": "Режим 2C: Название статьи ('Securing Wealth in Poetry') + чистый рассказ",
            "text": "Securing Wealth in Poetry\n" + story,
            "desc": "название статьи + рассказ"
        },
    ]

    print("Подготовленные раскладки текста:")
    for idx, l_info in enumerate(layouts, 1):
        ws_tok = tokenize_whitespace(l_info["text"])
        bip_tok = [w.lower() for w in ws_tok if w.lower() in word_to_idx]
        print(f"  [{idx}] {l_info['name']}")
        print(f"      Всего слов (WS): {len(ws_tok)}, BIP-39 слов: {len(bip_tok)}")
    print("=" * 75)

    # 4. База координат гео-локаций (все ключевые точки статьи и контекста)
    locations = [
        # Циндао (Qingdao)
        ("Циндао Мэрия (Wikipedia)", "360669", "120383"),
        ("Циндао Мэрия v2", "360669", "120382"),
        ("Циндао Порт Даган (Dagang)", "360936", "120317"),
        ("Циндао Порт Даган drop100", "360936", "203167"),
        ("Циндао Пассажирский морвокзал", "360872", "120315"),
        ("Циндао Вокзал Даган", "360844", "120321"),
        ("Циндао Пирс Чжаньцяо (Zhanqiao)", "360600", "120315"),
        ("Циндао Пирс Чжаньцяо drop100", "360600", "203148"),
        ("Циндао Павильон Хуэйланьгэ", "360583", "120316"),
        ("Циндао Железнодорожный вокзал", "360642", "120308"),
        ("Циндао Центр LatLong", "360671", "120383"),
        # Тайвань (Taiwan)
        ("Тайвань Порт Цзилун (Keelung)", "251311", "121743"),
        ("Тайвань Порт Цзилун drop100", "251311", "217431"),
        ("Тайвань Цзилун Морвокзал", "251325", "121741"),
        ("Тайвань Тайбэй City Hall", "250375", "121564"),
        ("Тайвань Тайбэй Main Station", "250478", "121517"),
        ("Тайвань Тайбэй Center LatLong", "250330", "121565"),
        # Оксфорд (Oxford)
        ("Оксфорд Jesus College (012569)", "517534", "012569"),
        ("Оксфорд Jesus College v2 (517533)", "517533", "012569"),
        ("Оксфорд Jesus College (125690)", "517534", "125690"),
        ("Оксфорд Jesus College OSM", "517533", "012555"),
        ("Оксфорд Бодлианская библиотека", "517539", "012544"),
        ("Оксфорд Бодлиан v2", "517537", "012541"),
        # Маунт-Вернон (Mount Vernon, Virginia)
        ("Маунт-Вернон Особняк (Wikipedia)", "387081", "770861"),
        ("Маунт-Вернон Особняк OSM", "387079", "770861"),
        ("Маунт-Вернон Территория", "387077", "770864"),
        # Иоганн Тритемий (Trithemius)
        ("Триттенхайм (Wikipedia 069006)", "498258", "069006"),
        ("Триттенхайм Мост (069011)", "498242", "069011"),
        ("Шпонхайм Аббатство (077250)", "498457", "077250"),
        ("Шпонхайм Деревня (077264)", "498458", "077264"),
        ("Шпонхайм Замок", "498317", "077147"),
        ("Вюрцбург Schottenkloster (099206)", "497956", "099206"),
        ("Вюрцбург Schottenkloster v2", "497953", "099206"),
        ("Вюрцбург Центр города", "497944", "099294"),
        # Династия Цинь (Qin Dynasty)
        ("Цинь Сяньян Дворец (Palace)", "344158", "108863"),
        ("Цинь Сяньян Руины города", "344139", "108858"),
        ("Цинь Сяньян Мэрия", "343300", "108709"),
        ("Цинь Мавзолей Цинь Шихуана", "343817", "109254"),
        ("Цинь Сиань Колокольня", "342610", "108942"),
        ("Цинь Сиань Мэрия", "343416", "108939"),
        # Канада (Canada - иммиграция дедушки)
        ("Ванкувер (Vancouver)1", "492827", "123120"),
        ("Ванкувер (Vancouver)2", "492827", "123121"),
        ("Торонто (Toronto)1", "436532", "079383"),
        ("Торонто (Toronto)2", "436532", "793832"),
        # Другие страны статьи
        ("Хараре (Зимбабве)", "178248", "310530"),
        ("Каракас (Венесуэла)", "104806", "669036"),
        ("Верховный суд США (Supreme Court)", "388906", "770044"),
    ]

    # Наборы чисел рассказа дедушки (12 и 13 чисел)
    story_numbers_12 = [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50]
    story_numbers_13_a = [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 5]    # первые 12 из 13
    story_numbers_13_b = [2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 5, 50]    # последние 12 из 13

    # Систематический диапазон смещений индексов (отрицательные, нулевые, положительные)
    INDEX_OFFSETS = [-3, -2, -1, 0, 1, 2, 3]

    start_time = time.time()

    # 5. Тестирование по всем раскладкам и токенизациям
    for l_info in layouts:
        mode_title = l_info["name"]
        text_content = l_info["text"]

        print(f"\n{'='*75}")
        print(f">>> ТЕСТИРОВАНИЕ РАСКЛАДКИ: {mode_title}")
        print(f"{'='*75}")

        # Проверяем две токенизации: Каноническую пробельную и регулярную буквенную
        tokenization_variants = [
            ("Пробельная (Каноническая)", tokenize_whitespace(text_content)),
            ("Регулярная (a-zA-Z)", tokenize_regex(text_content)),
        ]

        for tok_name, words_all in tokenization_variants:
            words_bip = [w.lower() for w in words_all if w.lower() in word_to_idx]
            len_all = len(words_all)
            len_bip = len(words_bip)

            print(f"\n  --- [Токенизация: {tok_name}] (Всего слов: {len_all}, BIP-39: {len_bip}) ---")

            # =====================================================================
            # АЛГОРИТМ 1: Канонический авторский Trithemius GPS по ВСЕМ словам текста
            # (index = digit + step * i + offset, как в авторском примере)
            # =====================================================================
            print("    [Алгоритм 1]: Авторский шаг Trithemius по ВСЕМ словам рассказа...")
            # Шаги: канонический авторский шаг 10, близкие шаги (9, 11), и масштабированные (15..52)
            gps_steps = [10, 9, 11, 15, 20, 25, 30, 35, 40, 45, 48, 50, 52]
            # Базовые смещения: начало от 0, от начала разных абзацев (с шагом 15 слов)
            base_offsets = [0, 10, 20, 30, 40, 50, 75, 100, 120, 150]

            for step in gps_steps:
                for name, lat, lon in locations:
                    for digits_str in [lat + lon, lon + lat]:
                        digits = [int(c) for c in digits_str if c.isdigit()]
                        if len(digits) < 12:
                            digits = (digits * 2)[:12]
                        else:
                            digits = digits[:12]

                        for base_off in base_offsets:
                            for offset in INDEX_OFFSETS:
                                # 1-based (авторская нумерация в тексте: 1, 2, ...)
                                idx_1 = [digits[i] + step * i + base_off + offset - 1 for i in range(12)]
                                if all(0 <= idx < len_all for idx in idx_1):
                                    w_cand_1 = [words_all[idx] for idx in idx_1]
                                    if all(w.lower() in word_to_idx for w in w_cand_1):
                                        desc_1 = f"{l_info['mode_id']} ({tok_name}) | А1 (Все слова 1-based, {name}, s={step}, base={base_off}, off={offset})"
                                        if check_phrase(w_cand_1, desc_1, word_to_idx):
                                            return

                                # 0-based
                                idx_0 = [digits[i] + step * i + base_off + offset for i in range(12)]
                                if all(0 <= idx < len_all for idx in idx_0):
                                    w_cand_0 = [words_all[idx] for idx in idx_0]
                                    if all(w.lower() in word_to_idx for w in w_cand_0):
                                        desc_0 = f"{l_info['mode_id']} ({tok_name}) | А1 (Все слова 0-based, {name}, s={step}, base={base_off}, off={offset})"
                                        if check_phrase(w_cand_0, desc_0, word_to_idx):
                                            return

                                # Модульная арифметика по всему тексту
                                idx_mod = [(digits[i] + step * i + base_off + offset) % len_all for i in range(12)]
                                w_cand_mod = [words_all[idx] for idx in idx_mod]
                                if all(w.lower() in word_to_idx for w in w_cand_mod):
                                    desc_mod = f"{l_info['mode_id']} ({tok_name}) | А1 (Все слова mod, {name}, s={step}, base={base_off}, off={offset})"
                                    if check_phrase(w_cand_mod, desc_mod, word_to_idx):
                                        return

            # =====================================================================
            # АЛГОРИТМ 2: Шаг по отфильтрованным BIP-39 словам рассказа
            # =====================================================================
            print("    [Алгоритм 2]: Шаг 10 (и 8, 9, 11, 12) по BIP-39 словам со смещениями...")
            for name, lat, lon in locations:
                for digits_str in [lat + lon, lon + lat]:
                    digits = [int(c) for c in digits_str if c.isdigit()]
                    if len(digits) < 12:
                        digits = (digits * 2)[:12]
                    else:
                        digits = digits[:12]

                    for step in [10, 9, 11, 8, 12]:
                        for start_mult in [0, 1]:
                            for offset in INDEX_OFFSETS:
                                # 0-based mod
                                idx_0 = [(digits[i] + step * (i + start_mult) + offset) % len_bip for i in range(12)]
                                w_cand_0 = [words_bip[i] for i in idx_0]
                                desc_0 = f"{l_info['mode_id']} ({tok_name}) | А2 (BIP 0-based, {name}, s={step}, mult={start_mult}, off={offset})"
                                if check_phrase(w_cand_0, desc_0, word_to_idx):
                                    return

                                # 1-based mod
                                idx_1 = [((digits[i] + step * (i + start_mult) - 1 + offset) % len_bip) for i in range(12)]
                                w_cand_1 = [words_bip[i] for i in idx_1]
                                desc_1 = f"{l_info['mode_id']} ({tok_name}) | А2 (BIP 1-based, {name}, s={step}, mult={start_mult}, off={offset})"
                                if check_phrase(w_cand_1, desc_1, word_to_idx):
                                    return

                                # Линейное индексирование без переполнения
                                idx_lin = [digits[i] + step * (i + start_mult) + offset for i in range(12)]
                                if all(0 <= idx < len_bip for idx in idx_lin):
                                    w_cand_lin = [words_bip[idx] for idx in idx_lin]
                                    desc_lin = f"{l_info['mode_id']} ({tok_name}) | А2 (BIP linear, {name}, s={step}, off={offset})"
                                    if check_phrase(w_cand_lin, desc_lin, word_to_idx):
                                        return

            # =====================================================================
            # АЛГОРИТМ 3: Арифметика по числам рассказа дедушки (12 и 13 чисел)
            # =====================================================================
            print("    [Алгоритм 3]: Числа рассказа (12/13 чисел, прямой, реверс, кумулятивно)...")
            num_sequences = [
                (story_numbers_12, "12 чисел"),
                (story_numbers_13_a, "13 чисел (первые 12)"),
                (story_numbers_13_b, "13 чисел (последние 12)"),
            ]

            for base_nums, num_label in num_sequences:
                for num_seq, order_label in [(base_nums, "прямой"), (base_nums[::-1], "реверс")]:
                    for offset in INDEX_OFFSETS:
                        # По BIP-словам 0-based
                        idx_bip_0 = [(n + offset) % len_bip for n in num_seq]
                        desc_bip_0 = f"{l_info['mode_id']} ({tok_name}) | А3 ({num_label}, mod BIP 0-based, {order_label}, off={offset})"
                        if check_phrase([words_bip[i] for i in idx_bip_0], desc_bip_0, word_to_idx):
                            return

                        # По BIP-словам 1-based
                        idx_bip_1 = [((n - 1 + offset) % len_bip) for n in num_seq]
                        desc_bip_1 = f"{l_info['mode_id']} ({tok_name}) | А3 ({num_label}, mod BIP 1-based, {order_label}, off={offset})"
                        if check_phrase([words_bip[i] for i in idx_bip_1], desc_bip_1, word_to_idx):
                            return

                        # По всем словам 0-based
                        idx_all_0 = [(n + offset) % len_all for n in num_seq]
                        w_cand_all_0 = [words_all[i] for i in idx_all_0]
                        if all(w.lower() in word_to_idx for w in w_cand_all_0):
                            desc_all_0 = f"{l_info['mode_id']} ({tok_name}) | А3 ({num_label}, mod All 0-based, {order_label}, off={offset})"
                            if check_phrase(w_cand_all_0, desc_all_0, word_to_idx):
                                return

                        # По всем словам 1-based
                        idx_all_1 = [((n - 1 + offset) % len_all) for n in num_seq]
                        w_cand_all_1 = [words_all[i] for i in idx_all_1]
                        if all(w.lower() in word_to_idx for w in w_cand_all_1):
                            desc_all_1 = f"{l_info['mode_id']} ({tok_name}) | А3 ({num_label}, mod All 1-based, {order_label}, off={offset})"
                            if check_phrase(w_cand_all_1, desc_all_1, word_to_idx):
                                return

                        # Кумулятивное смещение по BIP-словам
                        for start_val in [0, offset]:
                            cum_bip = []
                            curr = start_val
                            for n in num_seq:
                                curr = (curr + n + offset) % len_bip
                                cum_bip.append(curr)
                            desc_cum_bip = f"{l_info['mode_id']} ({tok_name}) | А3 ({num_label}, кумулятивно BIP, {order_label}, off={offset}, start={start_val})"
                            if check_phrase([words_bip[i] for i in cum_bip], desc_cum_bip, word_to_idx):
                                return

                        # Кумулятивное смещение по всем словам
                        cum_all = []
                        curr = 0
                        for n in num_seq:
                            curr = (curr + n + offset) % len_all
                            cum_all.append(curr)
                        w_cand_cum_all = [words_all[i] for i in cum_all]
                        if all(w.lower() in word_to_idx for w in w_cand_cum_all):
                            desc_cum_all = f"{l_info['mode_id']} ({tok_name}) | А3 ({num_label}, кумулятивно All, {order_label}, off={offset})"
                            if check_phrase(w_cand_cum_all, desc_cum_all, word_to_idx):
                                return

            # =====================================================================
            # АЛГОРИТМ 4: Числа координат срезами (2-значные и 3-значные)
            # =====================================================================
            print("    [Алгоритм 4]: Числа координат (2- и 3-значные срезы lat/lon)...")
            for name, lat, lon in locations:
                for num_str in [lat + lon, lon + lat]:
                    p3 = [int(num_str[i:i+3]) for i in range(0, len(num_str), 3)]
                    p3 = (p3 * 3)[:12]

                    p2 = [int(num_str[i:i+2]) for i in range(0, len(num_str), 2)]
                    p2 = (p2 * 2)[:12]

                    for parts, p_desc in [(p3, "3-значные"), (p2, "2-значные")]:
                        for offset in INDEX_OFFSETS:
                            # По BIP-словам 0-based
                            idx_bip_0 = [(n + offset) % len_bip for n in parts]
                            desc_bip_0 = f"{l_info['mode_id']} ({tok_name}) | А4 ({p_desc} mod BIP 0-based, {name}, off={offset})"
                            if check_phrase([words_bip[i] for i in idx_bip_0], desc_bip_0, word_to_idx):
                                return

                            # По BIP-словам 1-based
                            idx_bip_1 = [((n - 1 + offset) % len_bip) for n in parts]
                            desc_bip_1 = f"{l_info['mode_id']} ({tok_name}) | А4 ({p_desc} mod BIP 1-based, {name}, off={offset})"
                            if check_phrase([words_bip[i] for i in idx_bip_1], desc_bip_1, word_to_idx):
                                return

                            # По всем словам 0-based
                            idx_all_0 = [(n + offset) % len_all for n in parts]
                            w_cand_0 = [words_all[i] for i in idx_all_0]
                            if all(w.lower() in word_to_idx for w in w_cand_0):
                                desc_all_0 = f"{l_info['mode_id']} ({tok_name}) | А4 ({p_desc} mod All 0-based, {name}, off={offset})"
                                if check_phrase(w_cand_0, desc_all_0, word_to_idx):
                                    return

                            # По всем словам 1-based
                            idx_all_1 = [((n - 1 + offset) % len_all) for n in parts]
                            w_cand_1 = [words_all[i] for i in idx_all_1]
                            if all(w.lower() in word_to_idx for w in w_cand_1):
                                desc_all_1 = f"{l_info['mode_id']} ({tok_name}) | А4 ({p_desc} mod All 1-based, {name}, off={offset})"
                                if check_phrase(w_cand_1, desc_all_1, word_to_idx):
                                    return

                            # Кумулятивный вариант
                            cum_parts = []
                            curr = 0
                            for n in parts:
                                curr = (curr + n + offset) % len_bip
                                cum_parts.append(curr)
                            desc_cum = f"{l_info['mode_id']} ({tok_name}) | А4 ({p_desc} кумулятивно BIP, {name}, off={offset})"
                            if check_phrase([words_bip[i] for i in cum_parts], desc_cum, word_to_idx):
                                return

            # =====================================================================
            # АЛГОРИТМ 5: Скользящее окно по BIP-39 словам
            # =====================================================================
            print("    [Алгоритм 5]: Скользящее окно по BIP-39 словам (линейно, шаг 2, шаг 3)...")
            # Линейное окно 12 слов подряд
            for start_pos in range(len_bip - 11):
                window = words_bip[start_pos : start_pos + 12]
                desc_win = f"{l_info['mode_id']} ({tok_name}) | А5 (Окно BIP [{start_pos}:{start_pos + 12}])"
                if check_phrase(window, desc_win, word_to_idx):
                    return

            # Окно через одно слово (шаг 2)
            if len_bip >= 24:
                for start_pos in range(len_bip - 23):
                    window_even = words_bip[start_pos : start_pos + 24 : 2]
                    desc_even = f"{l_info['mode_id']} ({tok_name}) | А5 (Окно BIP через 1 [{start_pos}:{start_pos + 24}])"
                    if check_phrase(window_even, desc_even, word_to_idx):
                        return

            # Окно через два слова (шаг 3)
            if len_bip >= 36:
                for start_pos in range(len_bip - 35):
                    window_step3 = words_bip[start_pos : start_pos + 36 : 3]
                    desc_step3 = f"{l_info['mode_id']} ({tok_name}) | А5 (Окно BIP через 2 [{start_pos}:{start_pos + 36}])"
                    if check_phrase(window_step3, desc_step3, word_to_idx):
                        return

    # Сохраняем все найденные валидные BIP-39 фразы
    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        for entry in all_valid_found:
            f.write(entry + "\n")

    elapsed = time.time() - start_time
    print("\n" + "=" * 75)
    print("ИТОГИ АНАЛИЗА:")
    print(f"  • Всего проверено комбинаций индексов: {total_tested_combinations}")
    print(f"  • Найдено уникальных математически валидных BIP-39 мнемоник: {len(all_valid_found)}")
    print(f"  • Время выполнения: {elapsed:.2f} сек.")
    print(f"  • Все валидные фразы сохранены в: {CANDIDATES_FILE}")
    print(f"  • Статус проверки целевого адреса {TARGET_ADDRESS}:")
    print("    Среди проверенных алгоритмов точного совпадения с целевым адресом не найдено.")
    print("=" * 75)

if __name__ == "__main__":
    main()
