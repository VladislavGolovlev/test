"""
Высокопроизводительный скрипт тестирования Варианта 3:
«Классический шифр Иоганна Тритемия (Tabula Recta, Ave Maria, прогрессивный сдвиг +1)»
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
3. Живой непрерывный мониторинг прогресса в консоли (flush=True) и в progress_trithemius_cipher.txt.
4. Сохранение всех валидных по SHA-256 мнемоник в valid_trithemius_candidates.txt.
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
PROGRESS_FILE = BASE_DIR / "progress_trithemius_cipher.txt"
CANDIDATES_FILE = BASE_DIR / "valid_trithemius_candidates.txt"
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

class TrithemiusEvaluator:
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
                f.write(" МОНИТОРИНГ КЛАССИЧЕСКОГО ШИФРА ТРИТЕМИЯ (БЕЗ ПАРОЛЯ)\n")
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
        """Параллельно деривирует адреса с пустым паролем."""
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
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ ТРИТЕМИЯ!", flush=True)
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

def run_all_trithemius_tests():
    evaluator = TrithemiusEvaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА 3: КЛАССИЧЕСКИЙ ШИФР ТРИТЕМИЯ (БЕЗ ПАРОЛЯ)")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print("Пароль:         '' (ТОЛЬКО БЕЗ ПАРОЛЯ)")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ КЛАССИЧЕСКОГО ШИФРА ТРИТЕМИЯ ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]
    rev_paragraphs = paragraphs[2:11]
    rev_text = " ".join(rev_paragraphs)
    tokens_rev = clean_tokens(rev_text)
    bip_chain_rev = [w for w in tokens_rev if w in bip_set]

    para8_text = paragraphs[8]
    tokens_para8 = clean_tokens(para8_text)
    bip_chain_para8 = [w for w in tokens_para8 if w in bip_set]

    # Базовые 12-словные последовательности
    # 1. Верховный Суд (GPS пример)
    sc_words = "asset trial load escape symbol story bomb picnic river aerobic mystery honey".split()
    # 2. Пример телефонов (11 BIP слов + варианты для 11-го слова)
    phone_bases = []
    for fill in ["make", "good", "enough", "border", "valuable"]:
        phone_bases.append(f"faint lonely scale gate camera shoulder adult game medal language {fill} payment".split())
    # 3. Слова из абзаца 8 по GPS индексам Верховного суда
    gps_indices_1based = [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114]
    p8_gps_words_1 = [tokens_para8[i-1] for i in gps_indices_1based if i-1 < len(tokens_para8)]
    # 4. Слова из абзаца 8 по 0-based GPS индексам
    p8_gps_words_0 = [tokens_para8[i] for i in gps_indices_1based if i < len(tokens_para8)]
    # 5. Слова из Revolution по индексам телефонов
    phone_indices_1based = [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]
    rev_phone_words_1 = [tokens_rev[i-1] for i in phone_indices_1based if i-1 < len(tokens_rev)]
    rev_bip_phone_words = [bip_chain_rev[i-1] for i in phone_indices_1based if i-1 < len(bip_chain_rev)]

    # =========================================================================
    # ФАЗА 1: Tabula Recta на индексах BIP-39 слов (Прогрессивный сдвиг Тритемия)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 1]: Tabula Recta на индексах BIP-39 (Прогрессивные сдвиги +1, +10, k)...", flush=True)

    base_word_lists = [
        ("Supreme Court Example", sc_words),
        ("Paragraph 8 via GPS-1based", p8_gps_words_1),
        ("Paragraph 8 via GPS-0based", p8_gps_words_0),
        ("Revolution via Phone Indices", rev_phone_words_1),
        ("Revolution BIP-chain via Phone", rev_bip_phone_words),
    ]
    for pb in phone_bases:
        base_word_lists.append(("Phone Example", pb))

    def gen_tabula_recta_word_shifts():
        steps = [1, -1, 10, -10, 2, -2, 3, -3, 5, -5, 8, -8, 11, -11, 12, -12, 13, -13, 16, 26]
        offsets = range(-10, 11)
        for base_name, words in base_word_lists:
            if len(words) != 12:
                continue
            base_idxs = [word_to_idx.get(w) for w in words]
            if any(i is None for i in base_idxs):
                continue

            for step in steps:
                for k0 in offsets:
                    # Режим A: сдвиг всех 12 слов
                    shifted = [(base_idxs[i] + k0 + step * (i + 1)) % 2048 for i in range(12)]
                    cand = [wordlist[i] for i in shifted]
                    yield cand, f"TabulaRecta-{base_name}-step{step}-k0{k0}"

                    shifted_0 = [(base_idxs[i] + k0 + step * i) % 2048 for i in range(12)]
                    cand_0 = [wordlist[i] for i in shifted_0]
                    yield cand_0, f"TabulaRecta-{base_name}-step{step}-k0{k0}-0based"

                    # Режим B: сдвиг первых 11 слов, а 12-е подбирается по контрольной сумме SHA-256
    # ФАЗЫ 1 И 2 БЫЛИ ПОЛНОСТЬЮ ПРОВЕРЕНЫ (803,468 комбинаций, 791,577 сидов, 0 совпадений).
    SKIP_PHASE_1_2 = True
    if not SKIP_PHASE_1_2:
        if evaluator.test_combinations_stream(gen_tabula_recta_word_shifts(), 50000, "Фаза 1: Tabula Recta на BIP-39 индексах"):
            return True
        if evaluator.test_combinations_stream(gen_progressive_strides(), 120000, "Фаза 2: Прогрессивный шаг Тритемия по тексту"):
            return True
    else:
        print("\n[ИНФО]: Фазы 1 и 2 уже полностью выполнены в предыдущем прогоне (803,468 комбинаций). Переходим к Фазе 3.", flush=True)

    # =========================================================================
    # ФАЗА 3: Метод Ave Maria (Выборка по 12 блокам/абзацам/строкам)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 3]: Метод Ave Maria (Диагонали Тритемия по 12 блокам)...", flush=True)

    # Набор 1: 12 абзацев статьи с реальными BIP-словами (9 абзацев Revolution + 3 абзаца Fiat/Bitcoin)
    blocks_12_indices = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14]
    blocks_12 = []
    for idx in blocks_12_indices:
        b = [w for w in clean_tokens(paragraphs[idx]) if w in word_to_idx]
        blocks_12.append(b)

    # Набор 2: Разделение рассказа Revolution (608 слов) на 12 равных частей
    chunk_size = len(tokens_rev) // 12
    rev_chunks_12 = []
    for i in range(12):
        chunk = tokens_rev[i * chunk_size : (i + 1) * chunk_size]
        bips = [w for w in chunk if w in word_to_idx]
        rev_chunks_12.append(bips if bips else ["time"])

    # Набор 3: 12 предложений рассказа Revolution
    sentences_rev = [s.strip() for s in re.split(r'(?<=[.!?])\s+', rev_text) if s.strip()]
    sent_bips_12 = []
    for s in sentences_rev[:12]:
        b = [w for w in clean_tokens(s) if w in word_to_idx]
        sent_bips_12.append(b if b else ["time"])

    def gen_ave_maria_combinations():
        for group_name, blocks in [
            ("12 Blocks (Rev+Fiat+Btc)", blocks_12),
            ("12 Chunks Revolution", rev_chunks_12),
            ("12 Sentences Revolution", sent_bips_12),
        ]:
            if len(blocks) != 12 or any(len(b) == 0 for b in blocks):
                continue

            # 3.1 Фиксированные срезы Тритемия
            for mode, picker in [
                ("First BIP", lambda b, i: b[0]),
                ("Second BIP", lambda b, i: b[1] if len(b) > 1 else b[0]),
                ("Last BIP", lambda b, i: b[-1]),
                ("Trithemius Diagonal (i-th BIP)", lambda b, i: b[i % len(b)]),
                ("Trithemius AntiDiagonal", lambda b, i: b[(-1 - i) % len(b)]),
                ("Trithemius Shift Diagonal (+1)", lambda b, i: b[(i + 1) % len(b)]),
                ("Trithemius Shift Diagonal (+2)", lambda b, i: b[(i + 2) % len(b)]),
            ]:
                words = [picker(blocks[i], i) for i in range(12)]
                if any(w not in word_to_idx for w in words):
                    continue
                yield words, f"AveMaria-{group_name}-{mode}"
                yield list(reversed(words)), f"AveMariaRev-{group_name}-{mode}"

                first11 = [word_to_idx[w] for w in words[:11]]
                for l_idx in get_valid_last_words(first11):
                    yield words[:11] + [wordlist[l_idx]], f"AveMaria-CS-{group_name}-{mode}"

            # 3.2 Комбинаторный перебор первых 11 блоков (по топ-3 кандидатам) с точным расчетом 12-го слова!
            cands_per_block = [b[:3] for b in blocks[:11]]
            for choice11 in itertools.product(*cands_per_block):
                f11_idxs = [word_to_idx[w] for w in choice11]
                val_lasts = get_valid_last_words(f11_idxs)
                # Проверяем, есть ли 12-е слово среди кандидатов 12-го блока
                for l_idx in val_lasts:
                    last_w = wordlist[l_idx]
                    if last_w in blocks[11]:
                        yield list(choice11) + [last_w], f"AveMaria-Exact-{group_name}"

    if evaluator.test_combinations_stream(gen_ave_maria_combinations(), 200000, "Фаза 3: Метод Ave Maria"):
        return True

    # =========================================================================
    # ФАЗА 4: Tabula Recta на буквах (Letter-Level Progressive Caesar / Vigenere)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 4]: Tabula Recta на буквах (Сдвиги алфавита по Тритемию)...", flush=True)

    # Извлечение букв
    text_targets = [
        ("Revolution", tokens_rev),
        ("Paragraph 8", tokens_para8),
        ("Null Cipher Poem", clean_tokens(paragraphs[32])),
    ]

    def gen_letter_tabula_recta():
        for t_name, toks in text_targets:
            for letter_pos, l_desc in [
                (0, "1st Letter"),
                (1, "2nd Letter"),
                (2, "3rd Letter"),
                (-1, "Last Letter"),
            ]:
                chars = []
                for t in toks:
                    idx = letter_pos if letter_pos >= 0 else len(t) + letter_pos
                    if 0 <= idx < len(t):
                        chars.append(t[idx])

                if len(chars) < 36:
                    continue

                for step in [0, 1, -1, 2, -2, 3, -3, 5, 10]:
                    for k0 in range(26):
                        # Применяем прогрессивный сдвиг Тритемия
                        dec_chars = []
                        for j, ch in enumerate(chars):
                            val = ord(ch) - 97
                            if 0 <= val < 26:
                                shifted = (val - (k0 + step * j)) % 26
                                dec_chars.append(chr(shifted + 97))
                            else:
                                dec_chars.append(ch)

                        stream = "".join(dec_chars)
                        # Ищем слова BIP-39 в stream
                        found_bips = []
                        pos = 0
                        while pos < len(stream):
                            match = None
                            for w_len in range(8, 2, -1):
                                sub = stream[pos : pos + w_len]
                                if sub in bip_set:
                                    match = sub
                                    break
                            if match:
                                found_bips.append(match)
                                pos += len(match)
                            else:
                                pos += 1

                        if len(found_bips) >= 12:
                            for start_i in range(len(found_bips) - 11):
                                cand12 = found_bips[start_i : start_i + 12]
                                yield cand12, f"LetterTabula-{t_name}-{l_desc}-step{step}-k0{k0}"

    if evaluator.test_combinations_stream(gen_letter_tabula_recta(), 80000, "Фаза 4: Tabula Recta на буквах"):
        return True

    # =========================================================================
    # ФАЗА 5: Координаты ключевых мест Тритемия с авторской прогрессией
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 5]: Локации Тритемия (Sponheim, Trittenheim, Oxford, Frankfurt, Vatican)...", flush=True)

    trithemius_locations = {
        "Trittenheim (Birthplace)": "498258069006",
        "Sponheim Abbey": "498457077250",
        "Würzburg (Tomb)": "497956099206",
        "Jesus College, Oxford": "517534012569",
        "Bodleian Library, Oxford": "517539012544",
        "Frankfurt (Steganographia 1606)": "501109086821",
        "Vatican (Prohibited Books)": "419029124534",
        "Mount Vernon (Washington)": "387081770861",
    }

    def gen_trithemius_gps():
        steps = [10, 9, 8, 11, 12, 1]
        offsets = [-3, -2, -1, 0, 1, 2, 3]

        for loc_name, digits_str in trithemius_locations.items():
            digits = [int(c) for c in digits_str]
            for step in steps:
                for off in offsets:
                    # 1-based formula: d_i + step * i + off
                    idxs_1 = [digits[i] + step * (i + 1) + off for i in range(12)]
                    # 0-based formula: d_i + step * i + off
                    idxs_0 = [digits[i] + step * i + off for i in range(12)]

                    for formula_name, idx_list in [("1based", idxs_1), ("0based", idxs_0)]:
                        # Проверяем по Paragraph 8 (128 слов)
                        if all(0 <= idx < len(tokens_para8) for idx in idx_list):
                            w_p8 = [tokens_para8[idx] for idx in idx_list]
                            if all(w in bip_set for w in w_p8):
                                yield w_p8, f"TrithemiusGPS-{loc_name}-{formula_name}-step{step}-off{off}-P8"

                        # Проверяем по цепочке BIP-слов рассказа Revolution (112-121 слов)
                        if all(0 <= idx < len(bip_chain_rev) for idx in idx_list):
                            w_bip = [bip_chain_rev[idx] for idx in idx_list]
                            yield w_bip, f"TrithemiusGPS-{loc_name}-{formula_name}-step{step}-off{off}-RevBIP"

                        # Проверяем по прямому рассказу Revolution (608 слов)
                        if all(0 <= idx < len(tokens_rev) for idx in idx_list):
                            w_rev = [tokens_rev[idx] for idx in idx_list]
                            if all(w in bip_set for w in w_rev):
                                yield w_rev, f"TrithemiusGPS-{loc_name}-{formula_name}-step{step}-off{off}-Rev"

    if evaluator.test_combinations_stream(gen_trithemius_gps(), 40000, "Фаза 5: Локации Тритемия с прогрессией"):
        return True

    # =========================================================================
    # ФАЗА 6: Vigenere / Beaufort сдвиг по ключевым словам Тритемия
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 6]: Vigenere / Beaufort сдвиг на индексах по ключам Тритемия...", flush=True)

    trithemius_keys = [
        "trithemius",
        "steganographia",
        "polygraphia",
        "sponheim",
        "trittenheim",
        "frankfurt",
        "jesuscollege",
        "oxford",
        "avemaria",
        "cryptography",
    ]

    def gen_trithemius_vigenere():
        for base_name, words in base_word_lists:
            if len(words) != 12:
                continue
            base_idxs = [word_to_idx.get(w) for w in words]
            if any(i is None for i in base_idxs):
                continue

            for key in trithemius_keys:
                key_shifts = [ord(key[i % len(key)]) - 97 for i in range(12)]
                # Vigenere (+)
                cand_plus = [(base_idxs[i] + key_shifts[i]) % 2048 for i in range(12)]
                yield [wordlist[i] for i in cand_plus], f"VigenerePlus-{base_name}-key_{key}"

                # Vigenere (-)
                cand_minus = [(base_idxs[i] - key_shifts[i]) % 2048 for i in range(12)]
                yield [wordlist[i] for i in cand_minus], f"VigenereMinus-{base_name}-key_{key}"

                # Расчет контрольной суммы для первых 11 слов
                first11 = cand_plus[:11]
                for l_idx in get_valid_last_words(first11):
                    yield [wordlist[i] for i in first11] + [wordlist[l_idx]], f"VigenerePlus-CS-{base_name}-key_{key}"

    if evaluator.test_combinations_stream(gen_trithemius_vigenere(), 30000, "Фаза 6: Vigenere сдвиги по ключам"):
        return True

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ КЛАССИЧЕСКОГО ШИФРА ТРИТЕМИЯ ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)")
    print(f"Всего комбинаций: {evaluator.total_checked:,}")
    print(f"Валидных чексумм: {evaluator.valid_checksums:,}")
    print(f"Уникальных сидов: {evaluator.unique_seeds:,}")
    print(f"Затрачено времени: {elapsed:.2f} сек ({elapsed / 60:.2f} мин)")
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ КЛАССИЧЕСКОГО ШИФРА ТРИТЕМИЯ ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed / 60:.2f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

    return False

if __name__ == "__main__":
    run_all_trithemius_tests()
