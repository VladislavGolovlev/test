"""
Специализированный высокопроизводительный скрипт тестирования Гипотезы В:
«Числовой метод по числам главы "Revolution" (СТРОГО БЕЗ ПАРОЛЯ)»
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой адрес: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo

Числа главы Revolution:
- 1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50 (12 чисел)
- вариант с 13 числами (дополнительная 5): 1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 5, 50
- числа с учетом других глав: 1606, 2000, 1877, 1880, 2009, 2

Методы проецирования чисел:
1. Прямые индексы в словарь BIP-39 (все числа < 2048!).
   Проверка всех 16 вариантов контрольной суммы для 12-го слова, смещения +-1..5, 0-based и 1-based.
2. Проекция на BIP-слова рассказа Revolution (N ~ 112-121) через mod N и cumulative sums.
3. Проекция на общий поток слов рассказа Revolution (N ~ 597-622).
4. Телефонные индексы автора (2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116) со всеми смещениями.
5. Телефонные конструкции из цифр рассказа (Эрик и Карл).
"""

import sys
import os
import time
import re
import hashlib
import hmac
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
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
PROGRESS_FILE = BASE_DIR / "progress_numbers.txt"
CANDIDATES_FILE = BASE_DIR / "valid_numbers_candidates.txt"
FOUND_FILE = BASE_DIR / "FOUND_SOLUTION.txt"

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]
SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
NUM_THREADS = os.cpu_count() or 8

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
    salt = b"mnemonic"
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
                f.write(" МОНИТОРИНГ ГИПОТЕЗЫ В: ЧИСЛОВОЙ МЕТОД (СТРОГО БЕЗ ПАРОЛЯ)\n")
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

        if len(self.candidates_buffer) >= 100:
            with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
                f.writelines(self.candidates_buffer)
            self.candidates_buffer.clear()

        batch_size = 500
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
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ (ЧИСЛОВОЙ МЕТОД)!", flush=True)
                        print(f"Адрес:        {addr}", flush=True)
                        print(f"Мнемоника:    {phrase}", flush=True)
                        print(f"Путь:         {path} (compressed={comp})", flush=True)
                        print(f"Метаданные:   {meta}", flush=True)
                        print("!" * 75, flush=True)
                        with open(FOUND_FILE, "w", encoding="utf-8") as f:
                            f.write(f"ADDRESS: {addr}\nMNEMONIC: {phrase}\nPATH: {path}\nCOMP: {comp}\nMETA: {meta}\n")
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
        print(f"\n---> {phase_name} (оценка: ~{total_est:,} комбинаций)...", flush=True)
        t0 = time.time()
        batch_valid = []
        checked_here = 0

        for item in generator:
            checked_here += 1
            words_12, meta = item
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

def run_hypothesis_v_tests():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ГИПОТЕЗЫ В: ЧИСЛОВОЙ МЕТОД ПО РАССКАЗУ (СТРОГО БЕЗ ПАРОЛЯ)")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print("Пароль:         '' (ПУСТОЙ)")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ ЧИСЛОВОГО МЕТОДА ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]
    rev_text = " ".join(paragraphs[2:11])
    tokens_rev = clean_tokens(rev_text)
    bip_rev = [w for w in tokens_rev if w in bip_set]

    # Списки чисел:
    num_sets = {
        "Rev_12_no_dup5": [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50],
        "Rev_12_no_dup40": [1930, 2000, 1920, 6, 40, 10, 18, 5, 221, 206, 5, 50],
        "Rev_12_first12": [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 5],
        "Rev_12_last12": [2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 5, 50],
        "Rev_with_Ref_1": [1930, 2000, 1920, 6, 40, 10, 18, 5, 221, 206, 1606, 2020],
        "Rev_with_Ref_2": [1930, 2000, 1920, 6, 40, 10, 18, 5, 221, 206, 1877, 2009],
    }

    # =========================================================================
    # ГЕНЕРАТОР В1: Прямые индексы чисел в словарь BIP-39 (все числа < 2048!)
    # =========================================================================
    def gen_direct_bip_indices():
        for set_name, nums in num_sets.items():
            for base in (0, 1):
                for shift in range(-10, 11):
                    # Вариант А: берем первые 11 чисел, а 12-е перебираем по всем 128 словам, подходящим под чексумму
                    prefix_idxs = [(n - base + shift) % 2048 for n in nums[:11]]
                    val_prefix = 0
                    for idx in prefix_idxs:
                        val_prefix = (val_prefix << 11) | idx
                    val_prefix_shifted = val_prefix << 11

                    for last_word_idx in range(2048):
                        val_full = val_prefix_shifted | last_word_idx
                        ent = (val_full >> 4).to_bytes(16, "big")
                        cs = hashlib.sha256(ent).digest()[0] >> 4
                        if (val_full & 0x0F) == cs:
                            full_phrase = [wordlist[i] for i in prefix_idxs] + [wordlist[last_word_idx]]
                            yield full_phrase, f"Прямой BIP {set_name} (base={base}, shift={shift}, CS-matched last)"

                    # Вариант Б: все 12 чисел как есть
                    idxs_12 = [(n - base + shift) % 2048 for n in nums]
                    full_phrase_raw = [wordlist[i] for i in idxs_12]
                    yield full_phrase_raw, f"Прямой BIP {set_name} (base={base}, shift={shift}, raw)"

    evaluator.test_combinations_stream(gen_direct_bip_indices(), 50000, "Генератор В1: Прямые индексы в BIP-39")

    # =========================================================================
    # ГЕНЕРАТОР В2: Проекция чисел на BIP-слова рассказа Revolution (N ~ 112)
    # =========================================================================
    N_bip = len(bip_rev)
    def gen_rev_bip_numbers():
        for set_name, nums in num_sets.items():
            for shift in range(-15, 16):
                # 1. Modulo N
                idxs_mod = [(n + shift) % N_bip for n in nums]
                yield [bip_rev[i] for i in idxs_mod], f"BIP-цепь mod N {set_name} (shift={shift})"

                # 2. Last 2 digits mod N
                idxs_last2 = [(n % 100 + shift) % N_bip for n in nums]
                yield [bip_rev[i] for i in idxs_last2], f"BIP-цепь посл 2 цифры {set_name} (shift={shift})"

                # 3. Running cumulative sum mod N
                cumsum = 0
                cidxs = []
                for n in nums:
                    cumsum = (cumsum + n) % N_bip
                    cidxs.append(cumsum)
                yield [bip_rev[i] for i in cidxs], f"BIP-цепь cumsum {set_name} (shift={shift})"

                # 4. Running diffs / deltas
                deltas = [(nums[i] - nums[i-1] + shift) % N_bip for i in range(12)]
                yield [bip_rev[i] for i in deltas], f"BIP-цепь deltas {set_name} (shift={shift})"

    evaluator.test_combinations_stream(gen_rev_bip_numbers(), 20000, "Генератор В2: Числа mod N по BIP-цепи Revolution")

    # =========================================================================
    # ГЕНЕРАТОР В3: Телефонные индексы автора (Eric & Carl: 2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116)
    # =========================================================================
    author_phone_idxs = [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]
    def gen_phone_author_indices():
        for shift in range(-20, 21):
            for base in (0, 1):
                # По BIP-цепочке рассказа Revolution (112 слов)
                idxs_lin = [(p - base + shift) for p in author_phone_idxs]
                if all(0 <= i < N_bip for i in idxs_lin):
                    yield [bip_rev[i] for i in idxs_lin], f"Телефоны автора по BIP-цепи (base={base}, shift={shift})"

                idxs_mod = [(p - base + shift) % N_bip for p in author_phone_idxs]
                yield [bip_rev[i] for i in idxs_mod], f"Телефоны автора по BIP-цепи mod N (base={base}, shift={shift})"

                # По общему потоку слов рассказа Revolution (597 слов)
                N_tok = len(tokens_rev)
                idxs_tok = [(p - base + shift) for p in author_phone_idxs]
                if all(0 <= i < N_tok for i in idxs_tok):
                    phrase = [tokens_rev[i] for i in idxs_tok]
                    if all(w in bip_set for w in phrase):
                        yield phrase, f"Телефоны автора по потоку Revolution (base={base}, shift={shift})"

    evaluator.test_combinations_stream(gen_phone_author_indices(), 20000, "Генератор В3: Авторские телефонные индексы")

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ГИПОТЕЗЫ В ЗАВЕРШЕНО (СТРОГО БЕЗ ПАРОЛЯ)", flush=True)
    print(f"Всего комбинаций:           {evaluator.total_checked:,}", flush=True)
    print(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)", flush=True)
    print(f"Валидных чексумм:           {evaluator.valid_checksums:,}", flush=True)
    print(f"Уникальных сидов:           {evaluator.unique_seeds:,}", flush=True)
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ ГИПОТЕЗЫ В ЗАВЕРШЕНО\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

if __name__ == "__main__":
    run_hypothesis_v_tests()
