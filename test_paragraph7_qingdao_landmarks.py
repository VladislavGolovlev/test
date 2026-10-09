"""
Высокопроизводительный скрипт тестирования Варианта 1:
«Точечный анализ Абзаца 7/8 (128 слов про Циндао и побег с золотыми юаньбао)
по историческим координатам объектов Циндао и маршрута миграции»
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой адрес: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo
HASH160: c6233aeb3a50a70b82fcd88d69b5f1a3ec6e355a

Условия пользователя:
1. Проверка СТРОГО БЕЗ ПАРОЛЯ (passphrase = "").
2. Проверка по всем обязательным путям:
   - Мастер-ключ m напрямую (compressed и uncompressed)
   - BIP-44: m/44'/0'/0'/0/0..2 и m/44'/0'/0'/0 (compressed и uncompressed)
   - Legacy: m/0'/0'/0' (compressed и uncompressed)
   - Electrum: m/0/0 и m/0 (compressed и uncompressed)
3. Непрерывный мониторинг прогресса в консоли (flush=True) и в progress_paragraph7.txt.
4. Сохранение всех валидных по SHA-256 мнемоник в valid_paragraph7_candidates.txt.
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
PROGRESS_FILE = BASE_DIR / "progress_paragraph7.txt"
CANDIDATES_FILE = BASE_DIR / "valid_paragraph7_candidates.txt"
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

class Evaluator:
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
                f.write(" МОНИТОРИНГ ВАРИАНТА 1: ТОЧЕЧНЫЙ АНАЛИЗ АБЗАЦА 7/8 (БЕЗ ПАРОЛЯ)\n")
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
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ ВАРИАНТА 1!", flush=True)
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

# Географические координаты для Циндао, Тайваня и династии Цинь
QINGDAO_COORDINATES = {
    # 1. Пирс Чжаньцяо (главный исторический пирс Циндао с 1892 г.)
    "Zhanqiao Pier": ["360583120312", "360583203120", "360584120312", "360582120311"],
    # 2. Железнодорожный вокзал Циндао (1901 г., построен немцами, точка прибытия)
    "Qingdao Railway": ["360639120313", "360638120314", "360640120312"],
    # 3. Исторический порт Циндао / Даган (Dagang / Port of Qingdao)
    "Qingdao Port Dagang": ["360814120311", "360815120312", "360792120317"],
    # 4. Собор Св. Михаила (Католический собор 1934 г.)
    "St Michael Cathedral": ["360694120315", "360693120314"],
    # 5. Район Синань / Исторический центр Циндао
    "Shinan Downtown": ["360671120382", "360670120380"],
    # 6. Площадь 4 Мая / Мэрия Циндао
    "May Fourth Square": ["360617120380", "360618120381"],
    # 7. Бадагуань (Badaguan)
    "Badaguan Area": ["360538120354", "360540120355"],
    # 8. Остров Малый Циндао (Xiaoqingdao)
    "Little Qingdao": ["360526120316", "360525120315"],
    # 9. Столица династии Цинь (Сяньян / Сиань: "since the Qin dynasty [221 to 206 BC]")
    "Qin Dynasty Xianyang": ["343296108709", "343296087090", "343295108708"],
    "Qin Dynasty Xi'an": ["343416108939", "343415108940"],
    # 10. Порт Цзилун, Тайвань (точка прибытия на Тайвань)
    "Keelung Port Taiwan": ["251344121743", "251345121742", "251340121740"],
    # 11. Тайбэй, Тайвань
    "Taipei Taiwan": ["250330121565", "250332121567"],
}

# Комбинированные координаты маршрутов (например: 6 цифр Циндао + 6 цифр Тайваня)
COMBINED_ROUTES = {
    "Zhanqiao + Keelung": "360583121743",
    "Qingdao Port + Keelung": "360814121743",
    "Qingdao Railway + Keelung": "360639121743",
    "Qin Xianyang + Zhanqiao": "343296120312",
    "Qin Xianyang + Qingdao Port": "343296120311",
    "Zhanqiao + Taipei": "360583121565",
    "Qingdao Port + Taipei": "360814121565",
    "Keelung + Zhanqiao": "251344120312",
    # Маршрут из 3 точек по 4 цифры (Qin + Qingdao + Taiwan)
    "Qin4 + Qingdao4 + Taiwan4": "343236052513",
    "Qingdao4 + Taiwan4 + Canada4": "360525134927",
}

def run_paragraph7_tests():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА 1: ТОЧЕЧНЫЙ АНАЛИЗ АБЗАЦА 7/8 (БЕЗ ПАРОЛЯ)")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print("Пароль:         '' (ТОЛЬКО БЕЗ ПАРОЛЯ)")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ ВАРИАНТА 1 (БЕЗ ПАРОЛЯ) ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]

    # Абзац 8 (128 слов про отправку в Циндао и юаньбао династии Цинь)
    para8_text = paragraphs[8]
    raw_tokens_p8 = para8_text.split()
    tokens_p8 = clean_tokens(para8_text)
    bip_chain_p8 = [w for w in tokens_p8 if w in bip_set]

    # Абзац 9 (75 слов про прибытие в Циндао и отдачу 5 юаньбао кузену)
    para9_text = paragraphs[9]
    tokens_p9 = clean_tokens(para9_text)

    # Объединенный текст P8 + P9 (203 слова)
    tokens_p8_p9 = clean_tokens(para8_text + " " + para9_text)
    bip_chain_p8_p9 = [w for w in tokens_p8_p9 if w in bip_set]

    # Весь рассказ Revolution (608 слов, 112 BIP-слов)
    rev_text = " ".join(paragraphs[2:11])
    tokens_rev = clean_tokens(rev_text)
    bip_chain_rev = [w for w in tokens_rev if w in bip_set]

    print(f"Токенов в Абзаце 8 (пробельных): {len(raw_tokens_p8)}, чистых: {len(tokens_p8)}, BIP-слов: {len(bip_chain_p8)}")
    print(f"Токенов в Абзаце 8+9: {len(tokens_p8_p9)}, BIP-слов: {len(bip_chain_p8_p9)}")
    print(f"Токенов в Revolution: {len(tokens_rev)}, BIP-слов: {len(bip_chain_rev)}")

    # Все наборы координат
    all_coord_sets = {}
    for name, clist in QINGDAO_COORDINATES.items():
        for idx_c, c_str in enumerate(clist):
            key = f"{name}#{idx_c+1}" if len(clist) > 1 else name
            all_coord_sets[key] = c_str
    for name, c_str in COMBINED_ROUTES.items():
        all_coord_sets[f"Route-{name}"] = c_str

    print(f"Всего локаций и маршрутов для проверки: {len(all_coord_sets)}")

    # =========================================================================
    # ФАЗА 1: Прямое применение координат по формуле автора d_i + step * i
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 1]: Прямое применение координат по формуле автора (шаги 10, 9, 8, 11)...", flush=True)

    text_targets = [
        ("Paragraph 8 (128 words)", tokens_p8),
        ("Paragraph 8 Raw Tokens", [re.sub(r'^[^\w]+|[^\w]+$', '', t).lower() for t in raw_tokens_p8]),
        ("Paragraph 8+9 (203 words)", tokens_p8_p9),
        ("Paragraph 8 BIP-chain (24 words)", bip_chain_p8),
        ("Paragraph 8+9 BIP-chain (42 words)", bip_chain_p8_p9),
        ("Revolution BIP-chain (112 words)", bip_chain_rev),
    ]

    def gen_phase1_direct():
        steps = [10, 9, 8, 11, 12, 1]
        offsets = range(-5, 6)

        for loc_name, digits_str in all_coord_sets.items():
            if len(digits_str) != 12:
                continue
            digits = [int(c) for c in digits_str]

            for step in steps:
                for off in offsets:
                    # 1-based formula: d_i + step * i + off (где i = 0..11)
                    idxs_1 = [digits[i] + step * i + off for i in range(12)]
                    # 1-based с i = 1..12
                    idxs_1b = [digits[i] + step * (i + 1) + off for i in range(12)]
                    # 0-based: d_i + step * i + off - 1
                    idxs_0 = [digits[i] + step * i + off - 1 for i in range(12)]

                    for f_name, idx_list in [("1based_i0", idxs_1), ("1based_i1", idxs_1b), ("0based", idxs_0)]:
                        for t_name, toks in text_targets:
                            N = len(toks)
                            if all(0 <= idx < N for idx in idx_list):
                                cands = [toks[idx] for idx in idx_list]
                                if all(w in bip_set for w in cands):
                                    yield cands, f"Direct-{loc_name}-{t_name}-{f_name}-s{step}-off{off}"
                                    yield list(reversed(cands)), f"DirectRev-{loc_name}-{t_name}-{f_name}-s{step}-off{off}"

                                    # Расчет контрольной суммы для первых 11 слов
                                    first11 = [word_to_idx[w] for w in cands[:11]]
                                    for l_idx in get_valid_last_words(first11):
                                        yield cands[:11] + [wordlist[l_idx]], f"Direct-CS-{loc_name}-{t_name}-s{step}"

    if evaluator.test_combinations_stream(gen_phase1_direct(), 60000, "Фаза 1: Прямое применение координат"):
        return True

    # =========================================================================
    # ФАЗА 2: Proximity Search по Абзацу 8 (окрестность +-1..3 слова)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 2]: Proximity Search по Абзацу 8 (подбор ближайших BIP-слов в радиусе +-3)...", flush=True)

    # Индексируем BIP-слова в Абзаце 8 по позициям
    p8_bip_positions = []
    for pos, w in enumerate(tokens_p8):
        if w in bip_set:
            p8_bip_positions.append((pos, w))

    def find_nearby_bip_words(target_pos: int, radius: int = 3) -> list[str]:
        candidates = []
        for pos, w in p8_bip_positions:
            if abs(pos - target_pos) <= radius:
                candidates.append(w)
        return list(dict.fromkeys(candidates))

    def gen_phase2_proximity():
        for loc_name, digits_str in all_coord_sets.items():
            if len(digits_str) != 12:
                continue
            digits = [int(c) for c in digits_str]

            for step in [10, 9, 8, 11]:
                for off in [-2, -1, 0, 1, 2]:
                    target_indices = [digits[i] + step * i + off for i in range(12)]
                    # Для каждой позиции ищем ближайшие слова
                    slot_options = []
                    for t_pos in target_indices:
                        nearby = find_nearby_bip_words(t_pos, radius=3)
                        if not nearby:
                            nearby = find_nearby_bip_words(t_pos, radius=5)
                        slot_options.append(nearby if nearby else ["time"])

                    # Если для первых 11 слотов есть кандидаты, перебираем комбинации и считаем 12-е слово!
                    first11_options = [opts[:2] for opts in slot_options[:11]]
                    for combo11 in itertools.product(*first11_options):
                        f11_idxs = [word_to_idx[w] for w in combo11]
                        valid_12s = get_valid_last_words(f11_idxs)
                        for l_idx in valid_12s:
                            last_word = wordlist[l_idx]
                            if last_word in slot_options[11]:
                                yield list(combo11) + [last_word], f"Proximity-Exact-{loc_name}-s{step}-off{off}"

    if evaluator.test_combinations_stream(gen_phase2_proximity(), 150000, "Фаза 2: Proximity Search по Абзацу 8"):
        return True

    # =========================================================================
    # ФАЗА 3: Авторские индексы телефонов и Верховного Суда на Абзаце 8
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 3]: Индексы примера Supreme Court (3,18,28...) и Phones на Абзаце 8...", flush=True)

    author_index_sets = [
        ("Supreme Court (GPS)", [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114]),
        ("Phones (Eric & Carl)", [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]),
        ("GPS 0-based", [2, 17, 27, 38, 39, 55, 66, 76, 79, 89, 103, 113]),
        ("Phones 0-based", [1, 5, 8, 17, 21, 24, 44, 69, 85, 99, 112, 115]),
    ]

    def gen_phase3_author_indices():
        for idx_name, base_idxs in author_index_sets:
            for shift in range(-6, 7):
                shifted = [idx + shift for idx in base_idxs]
                for t_name, toks in [
                    ("Paragraph 8", tokens_p8),
                    ("Paragraph 8+9", tokens_p8_p9),
                    ("Revolution", tokens_rev),
                ]:
                    N = len(toks)
                    if all(0 <= idx < N for idx in shifted):
                        cands = [toks[idx] for idx in shifted]
                        if all(w in bip_set for w in cands):
                            yield cands, f"AuthorIdx-{idx_name}-{t_name}-shift{shift}"
                            yield list(reversed(cands)), f"AuthorIdxRev-{idx_name}-{t_name}-shift{shift}"

                            first11 = [word_to_idx[w] for w in cands[:11]]
                            for l_idx in get_valid_last_words(first11):
                                yield cands[:11] + [wordlist[l_idx]], f"AuthorIdx-CS-{idx_name}-{t_name}-shift{shift}"

                        # Proximity подбор для авторских индексов
                        slot_opts = []
                        for s_pos in shifted:
                            nearby = find_nearby_bip_words(s_pos, radius=2)
                            slot_opts.append(nearby if nearby else ["time"])

                        cands11 = [opts[:2] for opts in slot_opts[:11]]
                        for choice11 in itertools.product(*cands11):
                            f11_i = [word_to_idx[w] for w in choice11]
                            for l_idx in get_valid_last_words(f11_i):
                                if wordlist[l_idx] in slot_opts[11]:
                                    yield list(choice11) + [wordlist[l_idx]], f"AuthorProximity-{idx_name}-{t_name}-shift{shift}"

    if evaluator.test_combinations_stream(gen_phase3_author_indices(), 100000, "Фаза 3: Авторские индексы на Абзаце 8"):
        return True

    # =========================================================================
    # ФАЗА 4: Числовые маркеры Абзаца 8 (221, 206 BC, 5 taels, 5 yuanbao)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 4]: Числовые маркеры Абзаца 8 (221, 206, 5, 50, 1949)...", flush=True)

    # Числа, связанные с Абзацем 8:
    # 221 (династия Цинь начало), 206 (династия Цинь конец), 5 (пять таэлей / пять юаньбао), 50 (50 лет до возвращения)
    # Год основания Циндао: 1891 / 1892 / 1898
    # Год вокзала: 1901
    p8_numbers = [221, 206, 5, 5, 50, 1892, 1901, 1949, 1930, 2000, 1920, 6]

    def gen_phase4_numbers():
        # Вариант A: mod len(tokens_p8)
        N = len(tokens_p8)
        idxs_mod = [num % N for num in p8_numbers]
        for off in range(-5, 6):
            cur_idxs = [(idx + off) % N for idx in idxs_mod]
            cands = [tokens_p8[i] for i in cur_idxs]
            if all(w in bip_set for w in cands):
                yield cands, f"P8Numbers-mod-off{off}"
            first11 = [word_to_idx.get(w, 0) for w in cands[:11]]
            for l_idx in get_valid_last_words(first11):
                yield [wordlist[i] for i in first11] + [wordlist[l_idx]], f"P8Numbers-mod-CS-off{off}"

        # Вариант B: прямые BIP-39 индексы чисел
        direct_bip = [num % 2048 for num in p8_numbers]
        for off in range(-5, 6):
            cur_bip = [(idx + off) % 2048 for idx in direct_bip]
            cands = [wordlist[i] for i in cur_bip]
            yield cands, f"P8Numbers-BIP-off{off}"
            f11 = cur_bip[:11]
            for l_idx in get_valid_last_words(f11):
                yield [wordlist[i] for i in f11] + [wordlist[l_idx]], f"P8Numbers-BIP-CS-off{off}"

    if evaluator.test_combinations_stream(gen_phase4_numbers(), 50000, "Фаза 4: Числовые маркеры Абзаца 8"):
        return True

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА 1 ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)")
    print(f"Всего комбинаций: {evaluator.total_checked:,}")
    print(f"Валидных чексумм: {evaluator.valid_checksums:,}")
    print(f"Уникальных сидов: {evaluator.unique_seeds:,}")
    print(f"Затрачено времени: {elapsed:.2f} сек ({elapsed / 60:.2f} мин)")
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ ВАРИАНТА 1 ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed / 60:.2f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

    return False

if __name__ == "__main__":
    run_paragraph7_tests()
