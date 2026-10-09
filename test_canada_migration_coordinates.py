"""
Высокопроизводительный скрипт тестирования Варианта 2:
«Координаты канадской точки миграции дедушки и полного маршрута Циндао -> Тайвань -> Канада»
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой адрес: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo
HASH160: c6233aeb3a50a70b82fcd88d69b5f1a3ec6e355a

Цитата из статьи:
"He has since rebuilt his life twice, once as a refugee in Taiwan and again as an immigrant in Canada.
It would be 50 years until he returned to his ancestral home — he never saw his mother again."

Условия пользователя:
1. Проверка СТРОГО БЕЗ ПАРОЛЯ (passphrase = "").
2. Проверка по всем обязательным путям:
   - Мастер-ключ m напрямую (compressed и uncompressed)
   - BIP-44: m/44'/0'/0'/0/0..2 и m/44'/0'/0'/0 (compressed и uncompressed)
   - Legacy: m/0'/0'/0' (compressed и uncompressed)
   - Electrum: m/0/0 и m/0 (compressed и uncompressed)
3. Непрерывный мониторинг прогресса в консоли (flush=True) и в progress_canada.txt.
4. Сохранение всех валидных по SHA-256 мнемоник в valid_canada_candidates.txt.
"""

import sys
import os
import time
import re
import itertools
import hashlib
import hmac
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
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
PROGRESS_FILE = BASE_DIR / "progress_canada.txt"
CANDIDATES_FILE = BASE_DIR / "valid_canada_candidates.txt"
FOUND_FILE = BASE_DIR / "FOUND_SOLUTION.txt"

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]
SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
NUM_THREADS = os.cpu_count() or 8

# Загрузка словаря BIP-39
with open(WORDS_FILE, "r", encoding="utf-8") as f:
    wordlist = [w.strip().lower() for w in f if w.strip()]
word_to_idx = {w: i for i, w in enumerate(wordlist)}
bip_set = set(wordlist)

def verify_checksum(idxs_12: list[int] | tuple[int, ...]) -> bool:
    val = 0
    for idx in idxs_12:
        val = (val << 11) | idx
    entropy = (val >> 4).to_bytes(16, "big")
    expected_cs = hashlib.sha256(entropy).digest()[0] >> 4
    return (val & 0x0F) == expected_cs

def get_valid_last_words(idxs_11: list[int] | tuple[int, ...]) -> list[int]:
    """Для первых 11 слов находит все возможные индексы 12-го слова с валидным SHA-256."""
    prefix_val = 0
    for idx in idxs_11:
        prefix_val = (prefix_val << 11) | idx
    prefix_val <<= 11
    valid_lasts = []
    for last_idx in range(2048):
        val = prefix_val | last_idx
        entropy = (val >> 4).to_bytes(16, "big")
        expected_cs = hashlib.sha256(entropy).digest()[0] >> 4
        if (val & 0x0F) == expected_cs:
            valid_lasts.append(last_idx)
    return valid_lasts

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

def check_seed_all_paths(seed: bytes):
    """
    Проверяет сид по всем путям с пустым паролем:
    - Master key 'm' (compressed и uncompressed)
    - BIP-44: m/44'/0'/0'/0/0..2 и m/44'/0'/0'/0 (compressed и uncompressed)
    - Legacy BIP-32: m/0'/0'/0' (compressed и uncompressed)
    - Electrum: m/0/0 и m/0 (compressed и uncompressed)
    """
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]

    # 1. Master key 'm'
    for comp in (True, False):
        pub = coincurve.PrivateKey(master_k).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m", comp

    # 2. BIP-44: m/44'/0'/0'/0/0..2 и m/44'/0'/0'/0
    k44, c44 = ckd_priv(master_k, master_c, 44 + 0x80000000)
    if k44:
        k44_0, c44_0 = ckd_priv(k44, c44, 0 + 0x80000000)
        if k44_0:
            k44_0_0, c44_0_0 = ckd_priv(k44_0, c44_0, 0 + 0x80000000)
            if k44_0_0:
                k44_b, c44_b = ckd_priv(k44_0_0, c44_0_0, 0)
                if k44_b:
                    for comp in (True, False):
                        pub = coincurve.PrivateKey(k44_b).public_key.format(compressed=comp)
                        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                            return "m/44'/0'/0'/0", comp
                    for addr_idx in (0, 1, 2):
                        k_addr, _ = ckd_priv(k44_b, c44_b, addr_idx)
                        if k_addr:
                            for comp in (True, False):
                                pub = coincurve.PrivateKey(k_addr).public_key.format(compressed=comp)
                                if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                                    return f"m/44'/0'/0'/0/{addr_idx}", comp

    # 3. Legacy BIP-32: m/0'/0'/0'
    k0, c0 = ckd_priv(master_k, master_c, 0 + 0x80000000)
    if k0:
        k0_0, c0_0 = ckd_priv(k0, c0, 0 + 0x80000000)
        if k0_0:
            k0_0_0, _ = ckd_priv(k0_0, c0_0, 0 + 0x80000000)
            if k0_0_0:
                for comp in (True, False):
                    pub = coincurve.PrivateKey(k0_0_0).public_key.format(compressed=comp)
                    if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                        return "m/0'/0'/0'", comp

    # 4. Electrum / Legacy: m/0/0 и m/0
    km0, cm0 = ckd_priv(master_k, master_c, 0)
    if km0:
        for comp in (True, False):
            pub = coincurve.PrivateKey(km0).public_key.format(compressed=comp)
            if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                return "m/0", comp
        km0_0, _ = ckd_priv(km0, cm0, 0)
        if km0_0:
            for comp in (True, False):
                pub = coincurve.PrivateKey(km0_0).public_key.format(compressed=comp)
                if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                    return "m/0/0", comp

    return None

def check_phrase_task(item: tuple[str, str]):
    phrase, meta = item
    phrase_bytes = phrase.encode("utf-8")
    salt = b"mnemonic"  # СТРОГО БЕЗ ПАРОЛЯ
    seed = hashlib.pbkdf2_hmac("sha512", phrase_bytes, salt, 2048)
    match = check_seed_all_paths(seed)
    if match:
        path, comp = match
        return phrase, path, comp, meta
    return None

class CanadaEvaluator:
    def __init__(self):
        self.seen_mnemonics = set()
        self.total_checked = 0
        self.valid_checksums = 0
        self.unique_seeds = 0
        self.start_time = time.time()
        self.last_report = time.time()
        self.candidates_buffer = []

    def update_progress_file(self, pct: float, current: int, total: int, speed: float, el_str: str, eta_str: str, phase_name: str):
        try:
            with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
                f.write("======================================================================\n")
                f.write(" МОНИТОРИНГ ВАРИАНТА 2: КООРДИНАТЫ МИГРАЦИИ В КАНАДУ (БЕЗ ПАРОЛЯ)\n")
                f.write("======================================================================\n")
                f.write(f"Текущая фаза:     {phase_name}\n")
                f.write(f"Прогресс фазы:    {pct:.1f}% ({current:,} / {total:,})\n")
                f.write(f"Скорость:         {speed:,.1f} сид/сек\n")
                f.write(f"Прошедшее время:  {el_str}\n")
                f.write(f"Осталось (ETA):   {eta_str}\n")
                f.write(f"Всего комбинаций: {self.total_checked:,}\n")
                f.write(f"Валидных чексумм: {self.valid_checksums:,}\n")
                f.write(f"Уникальных сидов: {self.unique_seeds:,}\n")
                f.write("======================================================================\n")
        except Exception:
            pass

    def evaluate_phrases(self, items: list[tuple[str, str]], phase_name: str) -> bool:
        if not items:
            return False

        unique_items = []
        for phrase, meta in items:
            if phrase not in self.seen_mnemonics:
                self.seen_mnemonics.add(phrase)
                unique_items.append((phrase, meta))
                self.candidates_buffer.append(f"{phrase} | {meta}\n")

        self.unique_seeds += len(unique_items)
        if len(self.candidates_buffer) >= 50:
            with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
                f.writelines(self.candidates_buffer)
            self.candidates_buffer.clear()

        batch_size = 1000
        total_items = len(unique_items)
        processed = 0
        t_phase_start = time.time()

        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            for i in range(0, total_items, batch_size):
                chunk = unique_items[i : i + batch_size]
                results = list(executor.map(check_phrase_task, chunk))
                for res in results:
                    if res:
                        phrase, path, comp, meta = res
                        addr = base58.b58encode_check(b"\x00" + TARGET_H160).decode()
                        print("\n" + "!" * 75, flush=True)
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ ВАРИАНТА 2!", flush=True)
                        print(f"Адрес:        {addr}", flush=True)
                        print(f"Мнемоника:    {phrase}", flush=True)
                        print(f"Пароль:       '' (пустой)", flush=True)
                        print(f"Путь:         {path} (compressed={comp})", flush=True)
                        print(f"Метаданные:   {meta}", flush=True)
                        print("!" * 75, flush=True)
                        with open(FOUND_FILE, "w", encoding="utf-8") as f:
                            f.write(f"ADDRESS: {addr}\nMNEMONIC: {phrase}\nPASSPHRASE: \nPATH: {path}\nCOMP: {comp}\nMETA: {meta}\n")
                        return True

                processed += len(chunk)
                now = time.time()
                if now - self.last_report >= 2.0 or processed == total_items:
                    self.last_report = now
                    elapsed = now - self.start_time
                    phase_el = now - t_phase_start
                    spd = processed / phase_el if phase_el > 0 else 0
                    pct = (processed / total_items * 100.0) if total_items > 0 else 100.0
                    eta = (total_items - processed) / spd if spd > 0 else 0
                    eta_str = f"{int(eta // 60)}м {int(eta % 60):02d}с" if eta > 0 else "0с"
                    el_str = f"{int(elapsed // 60)}м {int(elapsed % 60):02d}с"
                    msg = (
                        f"[{pct:5.1f}%] {processed:>6d}/{total_items:<6d} сидов | "
                        f"Скорость: {spd:6.1f} сид/с | "
                        f"Прошло: {el_str} | ETA: {eta_str} | "
                        f"Фаза: {phase_name[:32]}"
                    )
                    print(msg, flush=True)
                    self.update_progress_file(pct, processed, total_items, spd, el_str, eta_str, phase_name)

        return False

    def test_combinations_stream(self, generator, total_est: int, phase_name: str) -> bool:
        print(f"\n---> {phase_name} (оценка: ~{total_est:,} комбинаций)...", flush=True)
        t0 = time.time()
        batch_valid = []
        checked_here = 0

        for item in generator:
            checked_here += 1
            if isinstance(item, tuple):
                words_12, meta = item
            else:
                words_12, meta = item, phase_name

            if len(words_12) != 12:
                continue
            idxs = [word_to_idx.get(w) for w in words_12]
            if any(i is None for i in idxs):
                continue
            if verify_checksum(idxs):
                batch_valid.append((" ".join(words_12), meta))

            if len(batch_valid) >= 5000:
                self.total_checked += checked_here
                self.valid_checksums += len(batch_valid)
                checked_here = 0
                if self.evaluate_phrases(batch_valid, phase_name):
                    return True
                batch_valid.clear()

        if batch_valid:
            self.total_checked += checked_here
            self.valid_checksums += len(batch_valid)
            if self.evaluate_phrases(batch_valid, phase_name):
                return True
            batch_valid.clear()
        else:
            self.total_checked += checked_here

        t_el = time.time() - t0
        print(f"     Фаза завершена за {t_el:.2f}с. Проверено комбинаций: {checked_here:,}", flush=True)
        return False

    def flush_candidates(self):
        if self.candidates_buffer:
            with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
                f.writelines(self.candidates_buffer)
            self.candidates_buffer.clear()

def clean_tokens(text: str) -> list[str]:
    raw = text.split()
    tokens = []
    for t in raw:
        c = re.sub(r"^[^\w]+|[^\w]+$", "", t).lower()
        if c:
            tokens.append(c)
    return tokens

# База координат канадских локаций и транзитных маршрутов
CANADA_LOCATIONS = {
    # Ванкувер (Chinatown, Pender St)
    "Vancouver Chinatown": ["492798123104", "492798231044", "492798023104", "492797123105"],
    # Порт Ванкувера / Burrard Inlet / Canada Place
    "Vancouver Port Burrard": ["492888123111", "492888231111", "492890123110"],
    # Центр Ванкувера
    "Vancouver Downtown": ["492827123120", "492827231207"],
    # Ричмонд (Golden Village, No 3 Rd - главный китайский город)
    "Richmond Golden Village": ["491824123136", "491824231362"],
    "Richmond City Hall": ["491666123133", "491666231336"],
    # Виктория (старейший Chinatown в Канаде)
    "Victoria Chinatown": ["484284123365", "484284233656", "484285123366"],
    "Victoria Inner Harbour": ["484222123368", "484222233680"],
    # Торонто Chinatown (Spadina & Dundas)
    "Toronto Chinatown": ["436532079398", "436532793980", "436533079397"],
    # Монреаль Chinatown
    "Montreal Chinatown": ["455088073559", "455088735592"],
    # Калгари Chinatown
    "Calgary Chinatown": ["510504114062", "510504140620"],
}

# Кросс-маршруты миграции: Тайвань/Циндао -> Канада
MIGRATION_ROUTES = {
    # Тайвань (Keelung / Taipei) -> Ванкувер (6 цифр + 6 цифр)
    "Keelung + Vancouver": "251344123104",
    "Taipei + Vancouver": "250330123104",
    "Keelung Lat + Vancouver Lat": "251344492798",
    "Taipei Lat + Vancouver Lat": "250330492798",
    "Vancouver + Keelung": "492798121743",
    "Vancouver + Taipei": "492798121565",
    "Vancouver Lat + Keelung Lat": "492798251344",

    # Циндао -> Канада (6 цифр + 6 цифр)
    "Zhanqiao + Vancouver": "360583123104",
    "Qingdao Port + Vancouver": "360814123104",
    "Zhanqiao Lat + Vancouver Lat": "360583492798",
    "Qingdao Port Lat + Vancouver Lat": "360814492798",
    "Qingdao Station + Vancouver": "360639492798",
    "Vancouver + Zhanqiao": "492798120312",
    "Vancouver + Qingdao Port": "492798120311",

    # Тайвань -> Ричмонд / Виктория / Торонто
    "Keelung + Richmond": "251344123133",
    "Keelung + Victoria": "251344123365",
    "Keelung + Toronto": "251344079398",

    # 3-этапный маршрут: 4 цифры Циндао + 4 цифры Тайвань + 4 цифры Канада (4+4+4=12)
    "Qingdao4 + Taiwan4 + Vancouver4": "360525134927",
    "Qingdao4 + Taiwan4 + VanLong4": "360525131231",
    "QingdaoPort4 + Keelung4 + VanPort4": "360825134928",
    "Qin4 + Taiwan4 + Canada4": "343225134927",
    "Canada4 + Taiwan4 + Qingdao4": "492725133605",
}

def run_canada_tests():
    evaluator = CanadaEvaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА 2: КООРДИНАТЫ МИГРАЦИИ В КАНАДУ (БЕЗ ПАРОЛЯ)")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print("Пароль:         '' (ТОЛЬКО БЕЗ ПАРОЛЯ)")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ ВАРИАНТА 2 (КАНАДА, БЕЗ ПАРОЛЯ) ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]

    # Абзац 9 (75 слов: "once as a refugee in Taiwan and again as an immigrant in Canada")
    para9_text = paragraphs[9]
    tokens_p9 = clean_tokens(para9_text)
    bip_chain_p9 = [w for w in tokens_p9 if w in bip_set]

    # Абзац 8 (128 слов)
    para8_text = paragraphs[8]
    tokens_p8 = clean_tokens(para8_text)
    bip_chain_p8 = [w for w in tokens_p8 if w in bip_set]

    # Абзац 8 + 9 (201 слово)
    tokens_p8_p9 = clean_tokens(para8_text + " " + para9_text)
    bip_chain_p8_p9 = [w for w in tokens_p8_p9 if w in bip_set]

    # Весь рассказ Revolution (608 слов, 112 BIP-слов)
    rev_text = " ".join(paragraphs[2:11])
    tokens_rev = clean_tokens(rev_text)
    bip_chain_rev = [w for w in tokens_rev if w in bip_set]

    print(f"Абзац 9 (Канада): {len(tokens_p9)} токенов, {len(bip_chain_p9)} BIP-слов")
    print(f"Абзац 8 (Циндао): {len(tokens_p8)} токенов, {len(bip_chain_p8)} BIP-слов")
    print(f"Абзац 8+9: {len(tokens_p8_p9)} токенов, {len(bip_chain_p8_p9)} BIP-слов")
    print(f"Весь рассказ: {len(tokens_rev)} токенов, {len(bip_chain_rev)} BIP-слов")

    # Сборка всех локаций
    all_canada_coords = {}
    for name, clist in CANADA_LOCATIONS.items():
        for idx_c, c_str in enumerate(clist):
            key = f"{name}#{idx_c+1}" if len(clist) > 1 else name
            all_canada_coords[key] = c_str
    for name, c_str in MIGRATION_ROUTES.items():
        all_canada_coords[f"Route-{name}"] = c_str

    print(f"Всего канадских локаций и маршрутов: {len(all_canada_coords)}")

    # =========================================================================
    # ФАЗА 1: Прямое применение канадских координат по формуле автора
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 1]: Прямое применение координат по формуле автора (шаги 10, 9, 8, 11, 12)...", flush=True)

    text_targets = [
        ("Paragraph 9 (Canada, 75w)", tokens_p9),
        ("Paragraph 9 BIP-chain (18w)", bip_chain_p9),
        ("Paragraph 8 (128w)", tokens_p8),
        ("Paragraph 8+9 (201w)", tokens_p8_p9),
        ("Paragraph 8+9 BIP-chain (42w)", bip_chain_p8_p9),
        ("Revolution BIP-chain (112w)", bip_chain_rev),
        ("Revolution (608w)", tokens_rev),
    ]

    def gen_phase1_direct_canada():
        steps = [10, 9, 8, 11, 12, 1]
        offsets = range(-5, 6)

        for loc_name, digits_str in all_canada_coords.items():
            if len(digits_str) != 12:
                continue
            digits = [int(c) for c in digits_str]

            for step in steps:
                for off in offsets:
                    # 1-based formula: d_i + step * i + off (i = 0..11)
                    idxs_1 = [digits[i] + step * i + off for i in range(12)]
                    # 1-based formula: d_i + step * (i + 1) + off
                    idxs_1b = [digits[i] + step * (i + 1) + off for i in range(12)]
                    # 0-based formula
                    idxs_0 = [digits[i] + step * i + off - 1 for i in range(12)]

                    for f_name, idx_list in [("1based_i0", idxs_1), ("1based_i1", idxs_1b), ("0based", idxs_0)]:
                        for t_name, toks in text_targets:
                            N = len(toks)
                            if all(0 <= idx < N for idx in idx_list):
                                cands = [toks[idx] for idx in idx_list]
                                if all(w in bip_set for w in cands):
                                    yield cands, f"CanadaDirect-{loc_name}-{t_name}-{f_name}-s{step}-off{off}"
                                    yield list(reversed(cands)), f"CanadaDirectRev-{loc_name}-{t_name}-{f_name}-s{step}-off{off}"

                                    first11 = [word_to_idx[w] for w in cands[:11]]
                                    for l_idx in get_valid_last_words(first11):
                                        yield cands[:11] + [wordlist[l_idx]], f"CanadaDirect-CS-{loc_name}-{t_name}-s{step}"

    if evaluator.test_combinations_stream(gen_phase1_direct_canada(), 80000, "Фаза 1: Прямое применение канадских координат"):
        return True

    # =========================================================================
    # ФАЗА 2: Proximity Search по Абзацу 9 и 8+9 (окрестность +-1..3 слова)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 2]: Proximity Search по Абзацу 9 и 8+9 (подбор ближайших BIP-слов)...", flush=True)

    def get_bip_positions(toks: list[str]) -> list[tuple[int, str]]:
        return [(pos, w) for pos, w in enumerate(toks) if w in bip_set]

    p9_bip_pos = get_bip_positions(tokens_p9)
    p8_p9_bip_pos = get_bip_positions(tokens_p8_p9)

    def find_nearby(pos_list: list[tuple[int, str]], target_pos: int, radius: int = 3) -> list[str]:
        cands = [w for p, w in pos_list if abs(p - target_pos) <= radius]
        return list(dict.fromkeys(cands))

    def gen_phase2_proximity_canada():
        for t_label, t_toks, b_pos in [
            ("Paragraph 9", tokens_p9, p9_bip_pos),
            ("Paragraph 8+9", tokens_p8_p9, p8_p9_bip_pos),
        ]:
            for loc_name, digits_str in all_canada_coords.items():
                if len(digits_str) != 12:
                    continue
                digits = [int(c) for c in digits_str]

                for step in [10, 9, 8, 11]:
                    for off in [-2, -1, 0, 1, 2]:
                        target_indices = [digits[i] + step * i + off for i in range(12)]
                        slot_options = []
                        for t_pos in target_indices:
                            nearby = find_nearby(b_pos, t_pos, radius=3)
                            if not nearby:
                                nearby = find_nearby(b_pos, t_pos, radius=5)
                            slot_options.append(nearby if nearby else ["time"])

                        cands11 = [opts[:2] for opts in slot_options[:11]]
                        for combo11 in itertools.product(*cands11):
                            f11_idxs = [word_to_idx[w] for w in combo11]
                            val_lasts = get_valid_last_words(f11_idxs)
                            for l_idx in val_lasts:
                                if wordlist[l_idx] in slot_options[11]:
                                    yield list(combo11) + [wordlist[l_idx]], f"CanadaProximity-{loc_name}-{t_label}-s{step}-off{off}"

    if evaluator.test_combinations_stream(gen_phase2_proximity_canada(), 150000, "Фаза 2: Proximity Search по канадским точкам"):
        return True

    # =========================================================================
    # ФАЗА 3: Авторские индексы (Supreme Court и Phones) на Абзаце 9 и 8+9
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 3]: Авторские индексы примеров на канадских фрагментах...", flush=True)

    author_indices = [
        ("Supreme Court GPS", [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114]),
        ("Phones (Eric & Carl)", [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]),
        ("GPS 0-based", [2, 17, 27, 38, 39, 55, 66, 76, 79, 89, 103, 113]),
        ("Phones 0-based", [1, 5, 8, 17, 21, 24, 44, 69, 85, 99, 112, 115]),
    ]

    def gen_phase3_author_canada():
        for idx_name, base_idxs in author_indices:
            for shift in range(-6, 7):
                shifted = [idx + shift for idx in base_idxs]
                for t_name, toks in [
                    ("Paragraph 8+9", tokens_p8_p9),
                    ("Revolution", tokens_rev),
                ]:
                    N = len(toks)
                    if all(0 <= idx < N for idx in shifted):
                        cands = [toks[idx] for idx in shifted]
                        if all(w in bip_set for w in cands):
                            yield cands, f"AuthorCanada-{idx_name}-{t_name}-shift{shift}"
                            yield list(reversed(cands)), f"AuthorCanadaRev-{idx_name}-{t_name}-shift{shift}"

                            first11 = [word_to_idx[w] for w in cands[:11]]
                            for l_idx in get_valid_last_words(first11):
                                yield cands[:11] + [wordlist[l_idx]], f"AuthorCanada-CS-{idx_name}-{t_name}-shift{shift}"

    if evaluator.test_combinations_stream(gen_phase3_author_canada(), 50000, "Фаза 3: Авторские индексы на канадских текстах"):
        return True

    # =========================================================================
    # ФАЗА 4: Числовые маркеры миграции в Канаду (50 years, twice, 1949, 1999)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 4]: Числовые маркеры миграции (50 years, twice, 1949, 1999)...", flush=True)

    # Числа из Абзаца 9:
    # "rebuilt his life twice" -> 2
    # "once as a refugee in Taiwan" -> 1
    # "again as an immigrant in Canada" -> 1 (или 2)
    # "It would be 50 years until he returned" -> 50
    # Год исхода: ~1949 (18 лет) + 50 лет = ~1999
    # Год рождения: ~1930
    canada_numbers = [50, 2, 1, 1949, 1999, 1930, 2000, 1920, 6, 40, 10, 18]

    def gen_phase4_canada_numbers():
        # mod len(tokens_p8_p9)
        N = len(tokens_p8_p9)
        idxs_mod = [num % N for num in canada_numbers]
        for off in range(-5, 6):
            cur_idxs = [(idx + off) % N for idx in idxs_mod]
            cands = [tokens_p8_p9[i] for i in cur_idxs]
            if all(w in bip_set for w in cands):
                yield cands, f"CanadaNumbers-mod-off{off}"
            first11 = [word_to_idx.get(w, 0) for w in cands[:11]]
            for l_idx in get_valid_last_words(first11):
                yield [wordlist[i] for i in first11] + [wordlist[l_idx]], f"CanadaNumbers-mod-CS-off{off}"

        # BIP mod 2048
        bip_nums = [num % 2048 for num in canada_numbers]
        for off in range(-5, 6):
            cur_bip = [(idx + off) % 2048 for idx in bip_nums]
            cands = [wordlist[i] for i in cur_bip]
            yield cands, f"CanadaNumbers-BIP-off{off}"
            f11 = cur_bip[:11]
            for l_idx in get_valid_last_words(f11):
                yield [wordlist[i] for i in f11] + [wordlist[l_idx]], f"CanadaNumbers-BIP-CS-off{off}"

    if evaluator.test_combinations_stream(gen_phase4_canada_numbers(), 30000, "Фаза 4: Числовые маркеры миграции"):
        return True

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА 2 ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)")
    print(f"Всего комбинаций: {evaluator.total_checked:,}")
    print(f"Валидных чексумм: {evaluator.valid_checksums:,}")
    print(f"Уникальных сидов: {evaluator.unique_seeds:,}")
    print(f"Затрачено времени: {elapsed:.2f} сек ({elapsed / 60:.2f} мин)")
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ ВАРИАНТА 2 ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed / 60:.2f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

    return False

if __name__ == "__main__":
    run_canada_tests()
