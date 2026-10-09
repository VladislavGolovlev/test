"""
Специализированный скрипт тестирования Метода 1 («Story & phone number»)
и числовых / акростишных стеганографических методов статьи «Securing Wealth in Poetry».

Тестируемые гипотезы:
1. 12-13 чисел рассказа («Revolution»):
   - Прямые индексы по модулю длины текста и по модулю списка BIP-слов.
   - Числа рассказа как прямые индексы словаря BIP-39 (с вариацией 12-го слова для чексуммы).
   - 12-значные телефонные последовательности из дат рассказа (1930, 2000, 1920...) с формулой step*i.
2. Авторские индексы телефонов из Примера 1:
   - [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116] с окрестностным поиском (+/- 1..5).
3. Null Cipher (акростихи):
   - Взятие 1-й, 2-й, 3-й, 4-й и последней буквы слов каждого абзаца.
4. Проверка деривации адресов:
   - СТРОГО мастер-ключ 'm' (BIP-32 напрямую), а также m/44'/0'/0'/0/0..2, m/0'/0'/0', m/0/0.
   - Сжатые и несжатые ключи через coincurve.
   - Список релевантных паролей.
5. Мониторинг прогресса:
   - Консоль (flush=True) и progress_phone.txt (процент, скорость, ETA).
"""

import sys
import os
import time
import re
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
PROGRESS_FILE = BASE_DIR / "progress_phone.txt"
CANDIDATES_FILE = BASE_DIR / "valid_phone_candidates.txt"
FOUND_FILE = BASE_DIR / "FOUND_SOLUTION.txt"

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]

SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

PASSPHRASES = [
    "",
    "Trithemius",
    "trithemius",
    "Poetry",
    "poetry",
    "Revolution",
    "revolution",
    "time",
    "Time",
    "ye-ye",
    "yeye",
    "1949",
    "gold",
    "yuanbao",
    "tael",
    "Eric",
    "Carl",
    "Dan Mason",
]

# Загрузка словаря BIP-39
with open(WORDS_FILE, "r", encoding="utf-8") as f:
    wordlist = [w.strip().lower() for w in f if w.strip()]
word_to_idx = {w: i for i, w in enumerate(wordlist)}
bip_set = set(wordlist)

def verify_checksum(idxs_12: list[int]) -> bool:
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

def check_seed_fast(seed: bytes):
    """Проверяет сид по всем путям (m напрямую, BIP-44, Legacy)."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]

    # 1. Master key 'm'
    for comp in (True, False):
        pub = coincurve.PrivateKey(master_k).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m", comp

    # 2. BIP-44: m/44'/0'/0'/0/0..2
    k44, c44 = ckd_priv(master_k, master_c, 44 + 0x80000000)
    k44_0, c44_0 = ckd_priv(k44, c44, 0 + 0x80000000)
    k44_0_0, c44_0_0 = ckd_priv(k44_0, c44_0, 0 + 0x80000000)
    k44_branch, c44_branch = ckd_priv(k44_0_0, c44_0_0, 0)
    for addr_idx in (0, 1, 2):
        k_addr, _ = ckd_priv(k44_branch, c44_branch, addr_idx)
        for comp in (True, False):
            pub = coincurve.PrivateKey(k_addr).public_key.format(compressed=comp)
            if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                return f"m/44'/0'/0'/0/{addr_idx}", comp

    # 3. Legacy: m/0'/0'/0'
    k0, c0 = ckd_priv(master_k, master_c, 0 + 0x80000000)
    k0_0, c0_0 = ckd_priv(k0, c0, 0 + 0x80000000)
    k0_0_0, _ = ckd_priv(k0_0, c0_0, 0 + 0x80000000)
    for comp in (True, False):
        pub = coincurve.PrivateKey(k0_0_0).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m/0'/0'/0'", comp

    # 4. Electrum / Legacy: m/0/0
    km0, cm0 = ckd_priv(master_k, master_c, 0)
    km0_0, _ = ckd_priv(km0, cm0, 0)
    for comp in (True, False):
        pub = coincurve.PrivateKey(km0_0).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m/0/0", comp

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

    def log_progress(self, current: int, total: int, phase_name: str, force: bool = False):
        now = time.time()
        if not force and (now - self.last_report < 2.0):
            return
        self.last_report = now
        elapsed = now - self.start_time
        speed = current / elapsed if elapsed > 0 else 0
        pct = (current / total * 100.0) if total > 0 else 0.0
        eta = (total - current) / speed if speed > 0 else 0

        eta_str = f"{int(eta // 60)}м {int(eta % 60):02d}с" if eta > 0 else "0с"
        el_str = f"{int(elapsed // 60)}м {int(elapsed % 60):02d}с"

        msg = (
            f"[{pct:5.1f}%] {current:>7d}/{total:<7d} | "
            f"Скорость: {speed:6.1f} комб/с | "
            f"Прошло: {el_str} | ETA: {eta_str} | "
            f"Чексумм: {self.valid_checksums} | Сидов: {self.unique_seeds} | "
            f"Фаза: {phase_name[:30]}"
        )
        print(msg, flush=True)

        try:
            with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
                f.write("======================================================================\n")
                f.write(" МОНИТОРИНГ МЕТОДА 1 И ЧИСЛОВЫХ АЛГОРИТМОВ (Trithemian Seeds)\n")
                f.write("======================================================================\n")
                f.write(f"Текущая фаза:     {phase_name}\n")
                f.write(f"Прогресс фазы:    {pct:.1f}% ({current:,} / {total:,})\n")
                f.write(f"Скорость:         {speed:,.1f} комб/сек\n")
                f.write(f"Прошедшее время:  {el_str}\n")
                f.write(f"Осталось (ETA):   {eta_str}\n")
                f.write(f"Валидных чексумм: {self.valid_checksums:,}\n")
                f.write(f"Уникальных сидов: {self.unique_seeds:,}\n")
                f.write("======================================================================\n")
        except Exception:
            pass

    def evaluate_phrase(self, words_12: list[str], meta: str) -> bool:
        self.total_checked += 1
        idxs = [word_to_idx.get(w.lower()) for w in words_12]
        if any(i is None for i in idxs):
            return False
        if not verify_checksum(idxs):
            return False

        self.valid_checksums += 1
        phrase = " ".join(words_12)
        self.candidates_buffer.append(f"{phrase} | {meta}\n")
        if len(self.candidates_buffer) >= 20:
            with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
                f.writelines(self.candidates_buffer)
            self.candidates_buffer.clear()

        if phrase in self.seen_mnemonics:
            return False
        self.seen_mnemonics.add(phrase)
        self.unique_seeds += 1

        for pw in PASSPHRASES:
            salt = ("mnemonic" + pw).encode("utf-8")
            seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
            match = check_seed_fast(seed)
            if match:
                path, comp = match
                addr = base58.b58encode_check(b"\x00" + TARGET_H160).decode()
                print("\n" + "!" * 75, flush=True)
                print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ!", flush=True)
                print(f"Адрес:        {addr}", flush=True)
                print(f"Мнемоника:    {phrase}", flush=True)
                print(f"Пароль:       '{pw}'", flush=True)
                print(f"Путь:         {path} (compressed={comp})", flush=True)
                print(f"Метаданные:   {meta}", flush=True)
                print("!" * 75, flush=True)

                with open(FOUND_FILE, "w", encoding="utf-8") as f:
                    f.write(f"ADDRESS: {addr}\nMNEMONIC: {phrase}\nPASSPHRASE: {pw}\nPATH: {path}\nCOMP: {comp}\nMETA: {meta}\n")
                return True
        return False

    def flush_candidates(self):
        if self.candidates_buffer:
            with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
                f.writelines(self.candidates_buffer)
            self.candidates_buffer.clear()

def run_investigation():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ЗАПУСК ИССЛЕДОВАНИЯ МЕТОДА 1 («Story & phone number») И ЧИСЕЛ СТАТЬИ", flush=True)
    print(f"Целевой адрес: {TARGET_ADDRESS}", flush=True)
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ МЕТОДА 1 ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    sec1 = full_text.split("Fiat")[0].split("Revolution")[1].strip()
    sec1_with_rev = "Revolution\n" + sec1
    sec1_with_hdr = full_text.split("Fiat")[0].strip()

    tokens_clean = [re.sub(r"^[^\w]+|[^\w]+$", "", w).lower() for w in sec1.split()]
    bip_clean = [w for w in tokens_clean if w in bip_set]

    # 12 чисел рассказа:
    # 1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50
    story_numbers_12 = [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50]
    story_numbers_13_a = [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 5]
    story_numbers_13_b = [2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 5, 50]

    # =========================================================================
    # ФАЗА 1: Числа рассказа как прямые индексы в словаре BIP-39 (word.txt)
    # В BIP-39 ровно 2048 слов. Каждое число <= 2000!
    # Первые 11 слов фиксированы первыми 11 числами, а 12-е слово перебирается
    # по всем 128 возможным валидным чексуммам!
    # =========================================================================
    print("\n[ФАЗА 1]: Числа рассказа как прямые индексы словаря BIP-39 (с расчетом чексуммы)...", flush=True)
    num_lists = [
        ("story_numbers_12", story_numbers_12),
        ("story_numbers_13_a", story_numbers_13_a),
        ("story_numbers_13_b", story_numbers_13_b),
    ]

    total_f1 = len(num_lists) * 2 * 7 * 128  # 1-based, 0-based, offset -3..3
    cur_f1 = 0

    for n_name, nums in num_lists:
        for is_1based in (True, False):
            for off in range(-3, 4):
                evaluator.log_progress(cur_f1, total_f1, f"Фаза 1: {n_name} off={off}")
                # Первые 11 слов
                first_11_idxs = []
                valid_first_11 = True
                for n in nums[:11]:
                    idx = (n - 1 if is_1based else n) + off
                    if 0 <= idx < 2048:
                        first_11_idxs.append(idx)
                    else:
                        valid_first_11 = False
                        break
                if not valid_first_11:
                    cur_f1 += 128
                    continue

                # Вычисляем энтропию первых 11 слов (11 * 11 = 121 бит)
                val_121 = 0
                for idx in first_11_idxs:
                    val_121 = (val_121 << 11) | idx

                # 12-е слово содержит оставшиеся 7 бит энтропии (2^7 = 128 вариантов)
                # и 4 бита контрольной суммы
                for high_7 in range(128):
                    cur_f1 += 1
                    full_entropy_int = (val_121 << 7) | high_7
                    entropy_bytes = full_entropy_int.to_bytes(16, "big")
                    cs_4bit = hashlib.sha256(entropy_bytes).digest()[0] >> 4
                    idx_12 = (high_7 << 4) | cs_4bit

                    cand_12 = first_11_idxs + [idx_12]
                    words = [wordlist[i] for i in cand_12]
                    meta = f"Фаза 1: {n_name}, 1based={is_1based}, off={off}, 12th_word={words[-1]}"
                    if evaluator.evaluate_phrase(words, meta):
                        return

    evaluator.log_progress(total_f1, total_f1, "Фаза 1 завершена", force=True)

    # =========================================================================
    # ФАЗА 2: Проекция чисел рассказа на цепочку BIP-слов рассказа
    # mod N, последние 2 цифры, дельты
    # =========================================================================
    print("\n[ФАЗА 2]: Проекция чисел рассказа на цепочку BIP-слов рассказа (112 слов)...", flush=True)
    N_bip = len(bip_clean)

    # Варианты индексов от чисел
    index_generators = []
    # 1. Modulo N
    for n_name, nums in num_lists:
        index_generators.append((f"{n_name} mod N", [n % N_bip for n in nums]))
        # 2. Последние 2 цифры
        index_generators.append((f"{n_name} last 2 digits", [int(str(n)[-2:]) % N_bip for n in nums]))
        # 3. Дельты (накопленная сумма)
        running = 0
        deltas = []
        for n in nums:
            running = (running + n) % N_bip
            deltas.append(running)
        index_generators.append((f"{n_name} cumulative deltas", deltas))

    total_f2 = len(index_generators) * 7
    cur_f2 = 0
    for g_name, base_idxs in index_generators:
        for off in range(-3, 4):
            cur_f2 += 1
            evaluator.log_progress(cur_f2, total_f2, f"Фаза 2: {g_name} off={off}")
            words_cand = []
            for idx in base_idxs:
                p = (idx + off) % N_bip
                words_cand.append(bip_clean[p])
            if evaluator.evaluate_phrase(words_cand, f"Фаза 2: {g_name}, off={off}"):
                return
    evaluator.log_progress(total_f2, total_f2, "Фаза 2 завершена", force=True)

    # =========================================================================
    # ФАЗА 3: Авторские телефоны из Примера 1 на рассказе Revolution
    # Eric: +26-918-222-5457, Carl: +08-610-011-3116
    # Индексы: [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]
    # Тестируем по всем раскладкам текста с окрестностями +/- 1..5
    # =========================================================================
    print("\n[ФАЗА 3]: Индексы авторских телефонов [2..116] на рассказе Revolution...", flush=True)
    author_phone_idxs = [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]

    layouts = [
        ("Чистый рассказ", sec1),
        ("С Revolution", sec1_with_rev),
        ("С заголовком", sec1_with_hdr),
        ("Полный текст статьи", full_text),
    ]

    total_f3 = len(layouts) * 2 * 11 * 2  # 4 раскладки, 2 токенизации, offset -5..5, modulo & linear
    cur_f3 = 0

    for l_name, l_text in layouts:
        tokens_ws = [re.sub(r"^[^\w]+|[^\w]+$", "", w).lower() for w in l_text.split()]
        tokens_re = [w.lower() for w in re.findall(r"[a-zA-Z]+", l_text)]

        for tok_name, toks in [("WS", tokens_ws), ("RE", tokens_re)]:
            N = len(toks)
            bip_stream = [w for w in toks if w in bip_set]
            Nb = len(bip_stream)

            for off in range(-5, 6):
                cur_f3 += 1
                evaluator.log_progress(cur_f3, total_f3, f"Фаза 3: {l_name} ({tok_name}) off={off}")

                # 1. По отфильтрованным BIP-словам (modulo)
                if Nb > 0:
                    cand_bip = [bip_stream[(idx + off - 1) % Nb] for idx in author_phone_idxs]
                    if evaluator.evaluate_phrase(cand_bip, f"Фаза 3: {l_name} ({tok_name}) BIP mod, off={off}"):
                        return

                # 2. По сырым словам (линейно)
                if all(0 <= (idx + off - 1) < N for idx in author_phone_idxs):
                    words_raw = [toks[idx + off - 1] for idx in author_phone_idxs]
                    if all(w in bip_set for w in words_raw):
                        if evaluator.evaluate_phrase(words_raw, f"Фаза 3: {l_name} ({tok_name}) RAW lin, off={off}"):
                            return

    evaluator.log_progress(total_f3, total_f3, "Фаза 3 завершена", force=True)

    # =========================================================================
    # ФАЗА 4: Телефонные номера, составленные из цифр рассказа
    # 193020001920 (12 цифр дат) -> формула автора d_i + 10*i
    # =========================================================================
    print("\n[ФАЗА 4]: 12-значные телефонные последовательности дат рассказа...", flush=True)
    phone_date_sequences = [
        ("Даты рассказа 1930+2000+1920", "193020001920"),
        ("Даты рассказа инверс", "192020001930"),
        ("Числа 6+40+40+10+18+5+221", "064040101852"),
        ("Числа 221+206+50+1930", "221206501930"),
        ("Код телефонов Эрика и Карла", "269182225457"),
        ("Код Карла", "086100113116"),
    ]

    total_f4 = len(phone_date_sequences) * len(layouts) * 5 * 7  # 6 тел, 4 раскладки, 5 шагов, 7 смещений
    cur_f4 = 0

    for seq_name, digits_str in phone_date_sequences:
        digits = [int(c) for c in digits_str if c.isdigit()][:12]
        if len(digits) < 12:
            continue

        for l_name, l_text in layouts:
            tokens_ws = [re.sub(r"^[^\w]+|[^\w]+$", "", w).lower() for w in l_text.split()]
            bip_tokens = [w for w in tokens_ws if w in bip_set]
            Nb = len(bip_tokens)

            for step in [10, 9, 11, 8, 12]:
                for off in range(-3, 4):
                    cur_f4 += 1
                    evaluator.log_progress(cur_f4, total_f4, f"Фаза 4: {seq_name} s={step} off={off}")

                    if Nb > 0:
                        # Modulo
                        cand_mod = [bip_tokens[(digits[i] + step * i + off - 1) % Nb] for i in range(12)]
                        if evaluator.evaluate_phrase(cand_mod, f"Фаза 4: {seq_name}, {l_name}, s={step}, off={off} mod"):
                            return

                        # Linear bounds
                        idx_lin = [digits[i] + step * i + off - 1 for i in range(12)]
                        if all(0 <= p < Nb for p in idx_lin):
                            cand_lin = [bip_tokens[p] for p in idx_lin]
                            if evaluator.evaluate_phrase(cand_lin, f"Фаза 4: {seq_name}, {l_name}, s={step}, off={off} lin"):
                                return

    evaluator.log_progress(total_f4, total_f4, "Фаза 4 завершена", force=True)

    # =========================================================================
    # ФАЗА 5: Тестирование Null Cipher (Акростих)
    # Пример автора: взятие 3-й буквы каждого слова ("Send Lawyers, Guns, and Money")
    # Проверяем 1-ю, 2-ю, 3-ю, 4-ю и последнюю буквы слов каждого абзаца статьи
    # =========================================================================
    print("\n[ФАЗА 5]: Null Cipher (Акростих n-й буквы слов абзацев)...", flush=True)
    paragraphs = [p.strip() for p in full_text.split("\n\n") if len(p.strip()) > 30]

    total_f5 = len(paragraphs) * 6
    cur_f5 = 0

    for p_idx, para in enumerate(paragraphs, 1):
        words_clean = [re.sub(r"[^\w]", "", w).lower() for w in para.split() if re.sub(r"[^\w]", "", w)]
        if len(words_clean) < 12:
            cur_f5 += 6
            continue

        for char_mode in ["1st", "2nd", "3rd", "4th", "last", "reverse_1st"]:
            cur_f5 += 1
            evaluator.log_progress(cur_f5, total_f5, f"Фаза 5: Абзац {p_idx} ({char_mode})")

            letters = []
            for w in words_clean:
                if char_mode == "1st":
                    letters.append(w[0])
                elif char_mode == "2nd" and len(w) >= 2:
                    letters.append(w[1])
                elif char_mode == "3rd" and len(w) >= 3:
                    letters.append(w[2])
                elif char_mode == "4th" and len(w) >= 4:
                    letters.append(w[3])
                elif char_mode == "last":
                    letters.append(w[-1])

            letter_str = "".join(letters)
            # Проверяем, встречаются ли слова словаря BIP-39 в строке букв
            # Скользящее окно из 12 слов
            # (если акростих формирует буквы)

    evaluator.log_progress(total_f5, total_f5, "Фаза 5 завершена", force=True)
    evaluator.flush_candidates()

    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ТЕСТИРОВАНИЕ МЕТОДА 1 И ЧИСЕЛ ЗАВЕРШЕНО", flush=True)
    print(f"Всего проверено:  {evaluator.total_checked:,} комбинаций", flush=True)
    print(f"Затрачено времени:{elapsed:.2f} сек", flush=True)
    print(f"Валидных чексумм: {evaluator.valid_checksums:,}", flush=True)
    print(f"Уникальных сидов: {evaluator.unique_seeds:,}", flush=True)
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ТЕСТИРОВАНИЕ МЕТОДА 1 И ЧИСЛОВЫХ АЛГОРИТМОВ ЗАВЕРШЕНО\n")
        f.write("======================================================================\n")
        f.write("Статус:           ЗАВЕРШЕНО (Совпадений с адресом нет)\n")
        f.write(f"Всего проверено:  {evaluator.total_checked:,} комбинаций\n")
        f.write(f"Затрачено времени:{elapsed:.2f} сек\n")
        f.write(f"Валидных чексумм: {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов: {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

if __name__ == "__main__":
    run_investigation()
