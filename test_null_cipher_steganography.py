"""
Специализированный высокопроизводительный скрипт тестирования Варианта 3:
«Комплексный Null Cipher / Метод Тритемия (N-я буква, шаги, акростихи)»
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой адрес: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo

Условия пользователя:
1. Проверка ТОЛЬКО БЕЗ ПАРОЛЯ (passphrase = "").
2. Проверка по всем требуемым путям:
   - Мастер-ключ 'm' напрямую (compressed и uncompressed)
   - BIP-44: m/44'/0'/0'/0/0..2, m/44'/0'/0'/0 (compressed и uncompressed)
   - Legacy: m/0'/0'/0', m/0/0, m/0 (compressed и uncompressed)
3. Живой мониторинг прогресса в консоли и в progress_nullcipher.txt.
4. Сохранение всех валидных по SHA-256 мнемоник в valid_nullcipher_candidates.txt.
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
PROGRESS_FILE = BASE_DIR / "progress_nullcipher.txt"
CANDIDATES_FILE = BASE_DIR / "valid_nullcipher_candidates.txt"
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
    Проверяет сид по всем требуемым путям с пустым паролем:
    - Мастер-ключ m (сжатый и несжатый)
    - BIP-44: m/44'/0'/0'/0/0..2 и m/44'/0'/0'/0 (сжатый и несжатый)
    - Legacy: m/0'/0'/0' (сжатый и несжатый)
    - Electrum / Legacy: m/0/0 и m/0 (сжатый и несжатый)
    """
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]

    # 1. Master key 'm'
    for comp in (True, False):
        pub = coincurve.PrivateKey(master_k).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m", comp

    # 2. BIP-44: m/44'/0'/0'/0/0..2 and m/44'/0'/0'/0
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

    # 4. Electrum / Legacy: m/0/0 and m/0
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
    salt = b"mnemonic"  # Пустой пароль
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
                f.write(" МОНИТОРИНГ NULL CIPHER / АКРОСТИХОВ (БЕЗ ПАРОЛЯ)\n")
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
        """Параллельно деривирует адреса в пуле потоков с пустым паролем."""
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
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ!", flush=True)
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
                        f"Фаза: {phase_name[:30]}"
                    )
                    print(msg, flush=True)
                    self.update_progress_file(pct, processed, total_items, spd, el_str, eta_str, phase_name)

        return False

    def test_combinations_stream(self, generator, total_est: int, phase_name: str) -> bool:
        """
        Принимает генератор 12-словных фраз, проверяет чексумму,
        и пачками отправляет валидные в многопоточный пул.
        """
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

def run_null_cipher_tests():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА 3: КОМПЛЕКСНЫЙ NULL CIPHER / АКРОСТИХИ")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print("Пароль:         '' (ТОЛЬКО БЕЗ ПАРОЛЯ)")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ NULL CIPHER (БЕЗ ПАРОЛЯ) ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]
    rev_text = " ".join(paragraphs[2:11])
    tokens_rev = clean_tokens(rev_text)
    bip_chain_rev = [w for w in tokens_rev if w in bip_set]

    # =========================================================================
    # ФАЗА 1: Null Cipher по предложениям рассказа «Revolution»
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 1]: Null Cipher по предложениям рассказа «Revolution»...", flush=True)
    raw_sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', rev_text) if s.strip()]
    sentences_bip = []
    for s in raw_sentences:
        toks = clean_tokens(s)
        bips = [w for w in toks if w in bip_set]
        if bips:
            sentences_bip.append(bips)

    print(f"  Выделено предложений с BIP-словами: {len(sentences_bip)}")

    # 1.1 Прямые 12 предложений (первые 12, последние 12)
    def gen_sentences_fixed():
        for label, fn in [
            ("1-е BIP-слово", lambda b: b[0]),
            ("2-е BIP-слово", lambda b: b[1] if len(b)>=2 else b[0]),
            ("3-е BIP-слово", lambda b: b[2] if len(b)>=3 else b[-1]),
            ("Последнее BIP-слово", lambda b: b[-1]),
            ("Предпоследнее BIP-слово", lambda b: b[-2] if len(b)>=2 else b[-1]),
        ]:
            # Первые 12 предложений
            p_first12 = [fn(b) for b in sentences_bip[:12]]
            yield p_first12, f"Предложения 1..12: {label}"
            # Последние 12 предложений
            if len(sentences_bip) >= 12:
                p_last12 = [fn(b) for b in sentences_bip[-12:]]
                yield p_last12, f"Предложения посл. 12: {label}"

    if evaluator.test_combinations_stream(gen_sentences_fixed(), 10, "Фаза 1.1: Фиксированные позиции предложений"):
        return

    # 1.2 Все сочетания 12 предложений из N (C(21, 12) = 293,930)
    # Для каждого сочетания берем: 1-е слово, 2-е слово, последнее слово
    N_sent = len(sentences_bip)
    def gen_sentences_combinations(word_selector, sel_label):
        for comb in itertools.combinations(range(N_sent), 12):
            phrase = [word_selector(sentences_bip[idx]) for idx in comb]
            yield phrase, f"C({N_sent},12): {sel_label}"

    total_combs = 293930
    if evaluator.test_combinations_stream(
        gen_sentences_combinations(lambda b: b[0], "1-е BIP-слово"),
        total_combs,
        "Фаза 1.2: C(N, 12) предложений (1-е слово)"
    ):
        return

    if evaluator.test_combinations_stream(
        gen_sentences_combinations(lambda b: b[-1], "Последнее BIP-слово"),
        total_combs,
        "Фаза 1.3: C(N, 12) предложений (Последнее слово)"
    ):
        return

    if evaluator.test_combinations_stream(
        gen_sentences_combinations(lambda b: b[1] if len(b)>=2 else b[0], "2-е BIP-слово"),
        total_combs,
        "Фаза 1.4: C(N, 12) предложений (2-е слово)"
    ):
        return

    # =========================================================================
    # ФАЗА 2: Периодический Null Cipher (Fixed-step skips)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 2]: Периодический Null Cipher (фиксированный шаг прореживания)...", flush=True)

    # 2.1 По цепочке BIP-39 слов рассказа Revolution (112 слов)
    def gen_periodic_bip_rev():
        for k in range(1, 20):
            for offset in range(k):
                seq = bip_chain_rev[offset::k]
                if len(seq) >= 12:
                    for start in range(len(seq) - 11):
                        yield seq[start:start+12], f"BIP Revolution (шаг {k}, смещ. {offset}, старт {start})"

    if evaluator.test_combinations_stream(gen_periodic_bip_rev(), 5000, "Фаза 2.1: Периодический шаг по BIP Revolution"):
        return

    # 2.2 По общему потоку слов рассказа Revolution (597 слов)
    def gen_periodic_all_rev():
        for k in range(1, 50):
            for offset in range(k):
                seq = tokens_rev[offset::k]
                if len(seq) >= 12:
                    for start in range(len(seq) - 11):
                        chunk = seq[start:start+12]
                        if all(w in bip_set for w in chunk):
                            yield chunk, f"Все слова Revolution (шаг {k}, смещ. {offset}, старт {start})"

    if evaluator.test_combinations_stream(gen_periodic_all_rev(), 5000, "Фаза 2.2: Периодический шаг по всем словам Revolution"):
        return

    # 2.3 По цепочке BIP-39 слов всей статьи (486 слов)
    tokens_all = clean_tokens(full_text)
    bip_chain_all = [w for w in tokens_all if w in bip_set]
    def gen_periodic_bip_all():
        for k in range(1, 41):
            for offset in range(k):
                seq = bip_chain_all[offset::k]
                if len(seq) >= 12:
                    for start in range(len(seq) - 11):
                        yield seq[start:start+12], f"BIP Вся статья (шаг {k}, смещ. {offset}, старт {start})"

    if evaluator.test_combinations_stream(gen_periodic_bip_all(), 15000, "Фаза 2.3: Периодический шаг по BIP всей статьи"):
        return

    # =========================================================================
    # ФАЗА 3: Дельты и шаги авторских индексов и чисел рассказа
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 3]: Дельты и шаги авторских телефонов и чисел рассказа...", flush=True)

    # 3.1 Авторские телефонные индексы Eric & Carl:
    # (2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116)
    author_idxs_base = [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]
    # Дельты:
    deltas = [author_idxs_base[i] - author_idxs_base[i-1] for i in range(1, len(author_idxs_base))]

    def gen_author_index_variations():
        for shift in range(-5, 6):
            # 1-based and 0-based
            shifted_1 = [idx + shift - 1 for idx in author_idxs_base]
            if all(0 <= i < len(bip_chain_rev) for i in shifted_1):
                yield [bip_chain_rev[i] for i in shifted_1], f"Телефоны автора по BIP Rev (shift={shift})"
            if all(0 <= i < len(tokens_rev) for i in shifted_1):
                ch = [tokens_rev[i] for i in shifted_1]
                if all(w in bip_set for w in ch):
                    yield ch, f"Телефоны автора по тексту Rev (shift={shift})"

    if evaluator.test_combinations_stream(gen_author_index_variations(), 50, "Фаза 3.1: Индексы телефонов автора"):
        return

    # 3.2 12 чисел рассказа Revolution:
    # [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50]
    nums_12 = [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50]
    def gen_story_number_mappings():
        # a) Модуло по длине BIP Revolution (112)
        N_bip = len(bip_chain_rev)
        for offset in range(-3, 4):
            idxs_mod = [(n + offset) % N_bip for n in nums_12]
            yield [bip_chain_rev[i] for i in idxs_mod], f"Числа рассказа % {N_bip} (off={offset})"

        # b) Последние 2 цифры как индексы: [30, 0, 20, 6, 40, 40, 10, 18, 5, 21, 6, 50]
        last2 = [n % 100 for n in nums_12]
        for offset in range(-3, 4):
            idxs_l2 = [(x + offset) % N_bip for x in last2]
            yield [bip_chain_rev[i] for i in idxs_l2], f"Посл. 2 цифры чисел (off={offset})"

        # c) Накопительная сумма дельт чисел (running deltas)
        for scale in [1, 2, 3]:
            cur = 0
            chain = []
            valid = True
            for n in nums_12:
                cur = (cur + (n % 20)) % N_bip
                chain.append(bip_chain_rev[cur])
            yield chain, f"Накопительные дельты чисел (scale={scale})"

    if evaluator.test_combinations_stream(gen_story_number_mappings(), 100, "Фаза 3.2: Числа рассказа Revolution"):
        return

    # =========================================================================
    # ФАЗА 4: Null Cipher по N-й букве слов (Acrostics / 3rd letter rule)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 4]: N-я буква слов (акростихи 1-й, 2-й, 3-й, последней буквы)...", flush=True)

    def gen_acrostic_phrases():
        # Для каждого предложения и каждого правила извлечения
        # смотрим, образуются ли последовательности BIP-слов
        for k_label, fn in [
            ("1-я буква", lambda w: w[0] if len(w)>=1 else ""),
            ("2-я буква", lambda w: w[1] if len(w)>=2 else ""),
            ("3-я буква", lambda w: w[2] if len(w)>=3 else ""),
            ("Посл. буква", lambda w: w[-1] if len(w)>=1 else ""),
        ]:
            stream = "".join(fn(w) for w in tokens_rev if fn(w).isalpha())
            # Ищем разбиения подстроки stream на 12 последовательных BIP-слов
            # Простой жадный и ветвящийся поиск:
            def find_12_words(pos, collected):
                if len(collected) == 12:
                    yield list(collected)
                    return
                if pos >= len(stream):
                    return
                for l in range(3, 9):
                    if pos + l <= len(stream):
                        w = stream[pos : pos + l]
                        if w in bip_set:
                            collected.append(w)
                            yield from find_12_words(pos + l, collected)
                            collected.pop()

            count_acr = 0
            for start_pos in range(min(50, len(stream))):
                for res in find_12_words(start_pos, []):
                    count_acr += 1
                    yield res, f"Акростих {k_label} (старт={start_pos})"
                    if count_acr >= 5000:
                        break
                if count_acr >= 5000:
                    break

    if evaluator.test_combinations_stream(gen_acrostic_phrases(), 20000, "Фаза 4: Акростихи по N-й букве"):
        return

    # =========================================================================
    # ФАЗА 5: Заглавные слова рассказа и статьи (Capitalized Acrostic)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ФАЗА 5]: Заглавные слова рассказа и статьи...", flush=True)

    proper_nouns_rev = [re.sub(r"^[^\w]+|[^\w]+$", "", w) for w in rev_text.split() if w and w[0].isupper()]
    proper_nouns_rev = [w.lower() for w in proper_nouns_rev if w.isalpha()]
    bip_caps_rev = [w for w in proper_nouns_rev if w in bip_set]
    print(f"  Заглавных слов в Revolution: {len(proper_nouns_rev)}, из них в BIP-39: {len(bip_caps_rev)}")

    proper_nouns_all = [re.sub(r"^[^\w]+|[^\w]+$", "", w) for w in full_text.split() if w and w[0].isupper()]
    proper_nouns_all = [w.lower() for w in proper_nouns_all if w.isalpha()]
    bip_caps_all = [w for w in proper_nouns_all if w in bip_set]
    print(f"  Заглавных слов во всей статье: {len(proper_nouns_all)}, из них в BIP-39: {len(bip_caps_all)}")

    def gen_capital_words_combinations():
        if len(bip_caps_all) >= 12:
            for s in range(len(bip_caps_all) - 11):
                yield bip_caps_all[s : s + 12], f"Слайдинг-окно заглавных BIP-слов (старт {s})"
        unique_caps = list(dict.fromkeys(bip_caps_all))
        if len(unique_caps) >= 12:
            for s in range(len(unique_caps) - 11):
                yield unique_caps[s : s + 12], f"Уникальные заглавные BIP-слова (старт {s})"
            for comb in itertools.combinations(unique_caps[:16], 12):
                yield list(comb), "C(16, 12) уникальных заглавных BIP-слов"

    if evaluator.test_combinations_stream(gen_capital_words_combinations(), 2000, "Фаза 5: Заглавные слова"):
        return

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ NULL CIPHER ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)", flush=True)
    print(f"Всего проверено комбинаций: {evaluator.total_checked:,}", flush=True)
    print(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)", flush=True)
    print(f"Валидных чексумм найдено:   {evaluator.valid_checksums:,}", flush=True)
    print(f"Уникальных сидов проверено: {evaluator.unique_seeds:,}", flush=True)
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ NULL CIPHER ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

if __name__ == "__main__":
    run_null_cipher_tests()
