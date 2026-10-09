"""
Специализированный высокопроизводительный скрипт тестирования Гипотезы Б:
«Проксимити-GPS (Neighborhood search) рассказа "Revolution" (СТРОГО БЕЗ ПАРОЛЯ)»
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой адрес: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo

Суть метода:
1. Вычисляется базовый целевой индекс каждого слова по формуле автора:
   target_idx = digit_i + step * i + offset
2. В окрестности target_idx (в диапазоне +-1..4 слов по общему потоку рассказа)
   находятся ближайшие слова, входящие в словарь BIP-39.
3. Формируются комбинации из 12 слов, проверяется контрольная сумма SHA-256 (BIP-39).
4. Валидные мнемоники проверяются на совпадение с адресом 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo
   по мастер-ключу m, BIP-44, Legacy и Electrum (со сжатыми и несжатыми ключами).
"""

import sys
import os
import time
import re
import hashlib
import hmac
import itertools
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
PROGRESS_FILE = BASE_DIR / "progress_proximity.txt"
CANDIDATES_FILE = BASE_DIR / "valid_proximity_candidates.txt"
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
                f.write(" МОНИТОРИНГ ГИПОТЕЗЫ Б: ПРОКСИМИТИ-GPS (СТРОГО БЕЗ ПАРОЛЯ)\n")
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
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ (ПРОКСИМИТИ-GPS)!", flush=True)
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

# Набор локаций для проксимити-анализа:
PROXIMITY_LOCATIONS = {
    # 1. Циндао (ключевая точка миграции дедушки)
    "Qingdao_City": "360671120382",
    "Qingdao_Port": "360814120311",
    "Qingdao_Pier": "360583120312",
    "Qingdao_Station": "360639120313",
    # 2. Тайвань (порт прибытия и столица)
    "Keelung_Port": "251344121743",
    "Taipei_City": "250330121565",
    # 3. Маршрут Циндао -> Тайвань (кросс-координаты)
    "Qingdao_Keelung": "360671251344",
    "Qingdao_Taipei": "360671250330",
    "QingdaoPort_Keelung": "360814121743",
    # 4. Верховный суд (эталон автора)
    "Supreme_Court": "388906770044",
    # 5. Другие исторические точки
    "Mount_Vernon": "387081770861",
    "Sponheim": "498457077250",
    "Trittenheim": "498258069006",
    "Caracas": "104806669036",
    "Harare": "178248310530",
    "Zim_Ven_Combo": "178248104806",
}

def run_hypothesis_b_tests():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ГИПОТЕЗЫ Б: ПРОКСИМИТИ-GPS (NEIGHBORHOOD SEARCH) (БЕЗ ПАРОЛЯ)")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print("Пароль:         '' (ПУСТОЙ)")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ ПРОКСИМИТИ-GPS ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]

    # Исследуем тексты:
    texts_to_test = {
        "Revolution": " ".join(paragraphs[2:11]),
        "Full_Article": full_text,
    }

    for name, text in texts_to_test.items():
        tokens = clean_tokens(text)
        N = len(tokens)
        bip_indices_in_stream = {i: tokens[i] for i in range(N) if tokens[i] in bip_set}
        print(f"\nАнализ текста '{name}': всего слов {N}, из них в BIP-39: {len(bip_indices_in_stream)}")

        def gen_proximity_phrases():
            # Шаги и смещения
            steps = [10, 9, 8, 11, 12, 7]
            for loc_name, coords in PROXIMITY_LOCATIONS.items():
                digits = [int(c) for c in coords]
                for step in steps:
                    for base in (0, 1):
                        for off in range(-3, 4):
                            # Для каждого из 12 индексов ищем ближайшие BIP-слова
                            slot_options = []
                            valid_slots = True
                            for i, d in enumerate(digits):
                                center = d + step * i - base + off
                                # Ищем в окрестности center +- radius
                                words_found = []
                                for delta in [0, 1, -1, 2, -2, 3, -3]:
                                    pos = center + delta
                                    if 0 <= pos < N and pos in bip_indices_in_stream:
                                        words_found.append(bip_indices_in_stream[pos])
                                        if len(words_found) >= 2:  # до 2 ближайших кандидатов на позицию
                                            break
                                if not words_found:
                                    valid_slots = False
                                    break
                                slot_options.append(words_found)

                            if valid_slots and len(slot_options) == 12:
                                # Декартово произведение найденных ближайших слов
                                for phrase_tuple in itertools.product(*slot_options):
                                    # Проверяем на вырожденность (слишком много одинаковых слов)
                                    counts = Counter(phrase_tuple)
                                    if max(counts.values()) <= 2:
                                        meta = f"{name} Proximity | {loc_name} (step={step}, base={base}, off={off})"
                                        yield list(phrase_tuple), meta

        evaluator.test_combinations_stream(
            gen_proximity_phrases(),
            100000,
            f"Проксимити-GPS по тексту '{name}'"
        )

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ГИПОТЕЗЫ Б ЗАВЕРШЕНО (СТРОГО БЕЗ ПАРОЛЯ)", flush=True)
    print(f"Всего проверено комбинаций: {evaluator.total_checked:,}", flush=True)
    print(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)", flush=True)
    print(f"Валидных чексумм:           {evaluator.valid_checksums:,}", flush=True)
    print(f"Уникальных сидов:           {evaluator.unique_seeds:,}", flush=True)
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ ГИПОТЕЗЫ Б ЗАВЕРШЕНО\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

if __name__ == "__main__":
    run_hypothesis_b_tests()
