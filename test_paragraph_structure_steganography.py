"""
Специализированный высокопроизводительный скрипт тестирования Гипотезы 1:
«1 абзац / блок = 1 слово» (Структурная стеганография)
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой кошелек: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo

Модели тестирования:
- МОДЕЛЬ 1: 12 структурных разделов статьи:
    1. Intro / Title
    2. Revolution (история дедушки)
    3. Fiat
    4. Bitcoin
    5. Touchpoints
    6. Steganography
    7. Trithemian Seeds
    8. Method 1 (Story & phone number)
    9. Example 1 (Palace Story)
    10. Method 2 (Letter & GPS location)
    11. Example 2 (Supreme Court)
    12. Conclusion
- МОДЕЛЬ 2: 12 абзацев повествования:
    Вариант А: Intro (1 абзац) + Revolution (9 абзацев) + Fiat (2 абзаца)
    Вариант Б: Revolution (9 абзацев) + Fiat (2 абзаца) + Bitcoin (1-й абзац)
- МОДЕЛЬ 3: 12 равных текстовых сегментов рассказа Revolution (~50 слов в сегменте)
- МОДЕЛЬ 4: 12 равных квантилей упорядоченной цепочки BIP-слов рассказа (112 слов)

Оптимизация:
- Мгновенная проверка 4-битной контрольной суммы BIP-39 (SHA-256) в памяти.
- Пул потоков (ThreadPoolExecutor на все ядра CPU) для вычисления PBKDF2 и деривации адресов через coincurve (libsecp256k1).
- Проверка мастер-ключа 'm' напрямую (compressed & uncompressed), BIP-44 и Legacy.
- Мониторинг прогресса в реальном времени в консоль и в файл progress_paragraphs.txt.
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
PROGRESS_FILE = BASE_DIR / "progress_paragraphs.txt"
CANDIDATES_FILE = BASE_DIR / "valid_paragraph_candidates.txt"
FOUND_FILE = BASE_DIR / "FOUND_SOLUTION.txt"

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]
SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
NUM_THREADS = os.cpu_count() or 8

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
    "1949",
    "gold",
    "Fiat",
    "fiat",
]

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

def check_seed_fast(seed: bytes):
    """Проверяет сид по мастер-ключу 'm' (compressed & uncompressed), BIP-44 и Legacy."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]

    # 1. Master key 'm'
    for comp in (True, False):
        pub = coincurve.PrivateKey(master_k).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m", comp

    # 2. BIP-44: m/44'/0'/0'/0/0..2
    k44, c44 = ckd_priv(master_k, master_c, 44 + 0x80000000)
    if k44:
        k44_0, c44_0 = ckd_priv(k44, c44, 0 + 0x80000000)
        if k44_0:
            k44_0_0, c44_0_0 = ckd_priv(k44_0, c44_0, 0 + 0x80000000)
            if k44_0_0:
                k44_b, c44_b = ckd_priv(k44_0_0, c44_0_0, 0)
                if k44_b:
                    for addr_idx in (0, 1, 2):
                        k_addr, _ = ckd_priv(k44_b, c44_b, addr_idx)
                        if k_addr:
                            for comp in (True, False):
                                pub = coincurve.PrivateKey(k_addr).public_key.format(compressed=comp)
                                if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                                    return f"m/44'/0'/0'/0/{addr_idx}", comp

    # 3. Legacy: m/0'/0'/0'
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

    # 4. Electrum / Legacy: m/0/0
    km0, cm0 = ckd_priv(master_k, master_c, 0)
    if km0:
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
    for pw in PASSPHRASES:
        salt = ("mnemonic" + pw).encode("utf-8")
        seed = hashlib.pbkdf2_hmac("sha512", phrase_bytes, salt, 2048)
        match = check_seed_fast(seed)
        if match:
            path, comp = match
            return phrase, pw, path, comp, meta
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
                f.write(" МОНИТОРИНГ СТРУКТУРНОЙ СТЕГАНОГРАФИИ («1 абзац = 1 слово»)\n")
                f.write("======================================================================\n")
                f.write(f"Текущая фаза:     {phase_name}\n")
                f.write(f"Прогресс фазы:    {pct:.1f}% ({current:,} / {total:,})\n")
                f.write(f"Скорость:         {speed:,.1f} комб/сек\n")
                f.write(f"Прошедшее время:  {el_str}\n")
                f.write(f"Осталось (ETA):   {eta_str}\n")
                f.write(f"Всего комбинаций: {self.total_checked:,}\n")
                f.write(f"Валидных чексумм: {self.valid_checksums:,}\n")
                f.write(f"Уникальных сидов: {self.unique_seeds:,}\n")
                f.write("======================================================================\n")
        except Exception:
            pass

    def evaluate_batches(self, valid_candidates: list[tuple[str, str]], phase_name: str) -> bool:
        """Параллельно вычисляет PBKDF2 и деривирует адреса в пуле потоков."""
        if not valid_candidates:
            return False

        # Фильтруем дубликаты мнемоник
        unique_items = []
        for phrase, meta in valid_candidates:
            if phrase not in self.seen_mnemonics:
                self.seen_mnemonics.add(phrase)
                unique_items.append((phrase, meta))
                self.candidates_buffer.append(f"{phrase} | {meta}\n")

        self.unique_seeds += len(unique_items)
        if len(self.candidates_buffer) >= 20:
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
                        phrase, pw, path, comp, meta = res
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
                    self.update_progress_file(pct, processed, total_items, spd, el_str, eta_str, f"{phase_name} (крипто-проверка)")

        return False

    def test_cartesian(self, slot_words: list[list[str]], phase_name: str) -> bool:
        """
        Тестирует декартово произведение 12 слотов:
        1. Мгновенно фильтрует валидные по чексумме комбинации.
        2. Проверяет их в многопоточном пуле.
        """
        slot_idxs = []
        for slot in slot_words:
            idxs = [word_to_idx[w] for w in slot if w in word_to_idx]
            slot_idxs.append(idxs)

        total_combs = 1
        for s in slot_idxs:
            total_combs *= len(s)

        print(f"\n---> {phase_name}: генерация и проверка чексумм для {total_combs:,} комбинаций...", flush=True)
        t0 = time.time()
        valid_candidates = []
        checked_here = 0

        for comb_idxs in itertools.product(*slot_idxs):
            checked_here += 1
            if verify_checksum(comb_idxs):
                words = [wordlist[i] for i in comb_idxs]
                phrase = " ".join(words)
                valid_candidates.append((phrase, phase_name))

        t_cs = time.time() - t0
        self.total_checked += checked_here
        self.valid_checksums += len(valid_candidates)
        print(f"     Проверено чексумм за {t_cs:.2f}с: найдено {len(valid_candidates):,} валидных мнемоник!", flush=True)

        # Многопоточная проверка сидов
        return self.evaluate_batches(valid_candidates, phase_name)

    def test_single_patterns(self, pattern_phrases: list[tuple[str, list[str]]], phase_name: str) -> bool:
        valid_items = []
        for pat_label, words_12 in pattern_phrases:
            self.total_checked += 1
            if len(words_12) != 12:
                continue
            idxs = [word_to_idx.get(w) for w in words_12]
            if any(i is None for i in idxs):
                continue
            if verify_checksum(idxs):
                self.valid_checksums += 1
                phrase = " ".join(words_12)
                valid_items.append((phrase, f"{phase_name} | {pat_label}"))
                print(f"  [Валидная мнемоника]: {pat_label} -> {phrase}", flush=True)

        if valid_items:
            return self.evaluate_batches(valid_items, phase_name)
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

def extract_patterns(slots_bip: list[list[str]]) -> list[tuple[str, list[str]]]:
    """Извлекает фиксированные позиционные паттерны для 12 слотов."""
    patterns = []
    # 1. Первое слово
    p1 = [b[0] for b in slots_bip if len(b) >= 1]
    if len(p1) == 12: patterns.append(("1-е BIP-слово", p1))

    # 2. Второе слово
    p2 = [b[1] if len(b) >= 2 else b[0] for b in slots_bip if b]
    if len(p2) == 12: patterns.append(("2-е BIP-слово", p2))

    # 3. Третье слово
    p3 = [b[2] if len(b) >= 3 else b[-1] for b in slots_bip if b]
    if len(p3) == 12: patterns.append(("3-е BIP-слово", p3))

    # 4. Последнее слово
    p_last = [b[-1] for b in slots_bip if len(b) >= 1]
    if len(p_last) == 12: patterns.append(("Последнее BIP-слово", p_last))

    # 5. Предпоследнее слово
    p_prev = [b[-2] if len(b) >= 2 else b[-1] for b in slots_bip if b]
    if len(p_prev) == 12: patterns.append(("Предпоследнее BIP-слово", p_prev))

    # 6. Медианное слово
    p_med = [b[len(b)//2] for b in slots_bip if len(b) >= 1]
    if len(p_med) == 12: patterns.append(("Медианное BIP-слово", p_med))

    return patterns

def run_paragraph_steganography():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ГИПОТЕЗЫ 1: «1 АБЗАЦ / БЛОК = 1 СЛОВО»")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ СТРУКТУРНОЙ СТЕГАНОГРАФИИ ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]

    # =========================================================================
    # МОДЕЛЬ 1: 12 структурных разделов всей статьи
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[МОДЕЛЬ 1]: 12 структурных разделов всей статьи...", flush=True)
    sections = [
        ("1. Intro", paragraphs[0]),
        ("2. Revolution", " ".join(paragraphs[2:11])),
        ("3. Fiat", " ".join(paragraphs[11:14])),
        ("4. Bitcoin", " ".join(paragraphs[14:19])),
        ("5. Touchpoints", " ".join(paragraphs[19:27])),
        ("6. Steganography", " ".join(paragraphs[28:36])),
        ("7. Trithemian Seeds", " ".join(paragraphs[36:39])),
        ("8. Method 1", paragraphs[39]),
        ("9. Example 1", paragraphs[40]),
        ("10. Method 2", paragraphs[41]),
        ("11. Example 2", paragraphs[42]),
        ("12. Conclusion", " ".join(paragraphs[43:47]))
    ]

    slots_mod1 = []
    for s_name, s_text in sections:
        toks = clean_tokens(s_text)
        bips = [w for w in toks if w in bip_set]
        slots_mod1.append(bips)
        print(f"  {s_name:<20}: слов {len(toks):3d}, BIP слов: {len(bips):3d}")

    # Фиксированные паттерны Модели 1
    pats_m1 = extract_patterns(slots_mod1)
    if evaluator.test_single_patterns(pats_m1, "Модель 1 (Паттерны)"):
        return

    # Декартово произведение top-3 слов каждого раздела (3^12 = 531,441)
    # Берем: первое слово, второе слово, последнее слово
    top3_slots_m1 = []
    for b in slots_mod1:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[1])
        if len(b) >= 3: opts.append(b[-1])
        top3_slots_m1.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(top3_slots_m1, "Модель 1: Декартово top-3 разделов"):
        return

    # Вариация Модели 1: первое слово, медианное слово, последнее слово
    med_slots_m1 = []
    for b in slots_mod1:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[len(b)//2])
        if len(b) >= 3: opts.append(b[-1])
        med_slots_m1.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(med_slots_m1, "Модель 1: Декартово (первое, медиана, последнее)"):
        return

    # =========================================================================
    # МОДЕЛЬ 2: 12 абзацев повествования
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[МОДЕЛЬ 2]: 12 абзацев повествования...", flush=True)

    # Вариант 2А: Введение (абзац 0) + Revolution (абзацы 2..10, 9 штук) + Fiat (абзацы 12, 13, 2 штуки)
    paras_2A = [paragraphs[0]] + paragraphs[2:11] + [paragraphs[12], paragraphs[13]]
    slots_2A = []
    print("  --- Вариант 2А: Intro + 9 абзацев Revolution + 2 абзаца Fiat ---")
    for i, p in enumerate(paras_2A, 1):
        toks = clean_tokens(p)
        bips = [w for w in toks if w in bip_set]
        slots_2A.append(bips)
        print(f"    Абзац {i:2d}: {len(bips):2d} BIP слов ({bips[:3]}...{bips[-1:] if bips else []})")

    pats_2A = extract_patterns(slots_2A)
    if evaluator.test_single_patterns(pats_2A, "Модель 2А (Паттерны)"):
        return

    top3_slots_2A = []
    for b in slots_2A:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[1])
        if len(b) >= 3: opts.append(b[-1])
        top3_slots_2A.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(top3_slots_2A, "Модель 2А: Декартово top-3 абзацев"):
        return

    # Вариант 2Б: 9 абзацев Revolution + 2 абзаца Fiat + 1 абзац Bitcoin
    paras_2B = paragraphs[2:11] + [paragraphs[12], paragraphs[13], paragraphs[14]]
    slots_2B = []
    print("  --- Вариант 2Б: 9 абзацев Revolution + 2 абзаца Fiat + 1 абзац Bitcoin ---")
    for i, p in enumerate(paras_2B, 1):
        toks = clean_tokens(p)
        bips = [w for w in toks if w in bip_set]
        slots_2B.append(bips)
        print(f"    Абзац {i:2d}: {len(bips):2d} BIP слов ({bips[:3]}...{bips[-1:] if bips else []})")

    pats_2B = extract_patterns(slots_2B)
    if evaluator.test_single_patterns(pats_2B, "Модель 2Б (Паттерны)"):
        return

    top3_slots_2B = []
    for b in slots_2B:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[1])
        if len(b) >= 3: opts.append(b[-1])
        top3_slots_2B.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(top3_slots_2B, "Модель 2Б: Декартово top-3 абзацев"):
        return

    # =========================================================================
    # МОДЕЛЬ 3: 12 равных текстовых сегментов рассказа Revolution (~50 слов)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[МОДЕЛЬ 3]: 12 равных сегментов текста Revolution (~50 слов на сегмент)...", flush=True)
    rev_full = " ".join(paragraphs[2:11])
    tokens_rev = clean_tokens(rev_full)
    N_words = len(tokens_rev)
    seg_size = N_words // 12
    print(f"  Всего слов в Revolution: {N_words}, размер сегмента: {seg_size} слов")

    slots_mod3 = []
    for i in range(12):
        start = i * seg_size
        end = (i + 1) * seg_size if i < 11 else N_words
        seg_toks = tokens_rev[start:end]
        seg_bips = [w for w in seg_toks if w in bip_set]
        slots_mod3.append(seg_bips)
        print(f"  Сегмент {i+1:2d} ({start:3d}..{end:3d}): BIP слов = {len(seg_bips)}: {seg_bips[:3]}")

    pats_m3 = extract_patterns(slots_mod3)
    if evaluator.test_single_patterns(pats_m3, "Модель 3 (Паттерны)"):
        return

    top3_slots_m3 = []
    for b in slots_mod3:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[1])
        if len(b) >= 3: opts.append(b[-1])
        top3_slots_m3.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(top3_slots_m3, "Модель 3: Декартово top-3 сегментов"):
        return

    # Вариант 3Б: первое, медиана, последнее
    med_slots_m3 = []
    for b in slots_mod3:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[len(b)//2])
        if len(b) >= 3: opts.append(b[-1])
        med_slots_m3.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(med_slots_m3, "Модель 3: Декартово (первое, медиана, последнее)"):
        return

    # =========================================================================
    # МОДЕЛЬ 4: 12 квантилей упорядоченной цепочки BIP-слов рассказа (112 слов)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[МОДЕЛЬ 4]: 12 квантилей упорядоченной цепочки BIP-слов рассказа (112 слов)...", flush=True)
    bip_chain = [w for w in tokens_rev if w in bip_set]
    N_bip = len(bip_chain)
    q_size = N_bip / 12.0

    slots_mod4 = []
    for i in range(12):
        s = int(round(i * q_size))
        e = int(round((i + 1) * q_size))
        q_words = bip_chain[s:e]
        slots_mod4.append(q_words)
        print(f"  Квантиль {i+1:2d} (индексы {s:2d}..{e:2d}): слов {len(q_words)}: {q_words}")

    pats_m4 = extract_patterns(slots_mod4)
    if evaluator.test_single_patterns(pats_m4, "Модель 4 (Паттерны)"):
        return

    top3_slots_m4 = []
    for b in slots_mod4:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[1])
        if len(b) >= 3: opts.append(b[-1])
        top3_slots_m4.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(top3_slots_m4, "Модель 4: Декартово top-3 квантилей"):
        return

    # Вариант 4Б: первое, медиана, последнее
    med_slots_m4 = []
    for b in slots_mod4:
        opts = []
        if len(b) >= 1: opts.append(b[0])
        if len(b) >= 2: opts.append(b[len(b)//2])
        if len(b) >= 3: opts.append(b[-1])
        med_slots_m4.append(list(dict.fromkeys(opts)))

    if evaluator.test_cartesian(med_slots_m4, "Модель 4: Декартово (первое, медиана, последнее)"):
        return

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ СТРУКТУРНОЙ СТЕГАНОГРАФИИ ЗАВЕРШЕНО", flush=True)
    print(f"Всего проверено комбинаций: {evaluator.total_checked:,}", flush=True)
    print(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)", flush=True)
    print(f"Валидных чексумм найдено:   {evaluator.valid_checksums:,}", flush=True)
    print(f"Уникальных сидов проверено: {evaluator.unique_seeds:,}", flush=True)
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ СТРУКТУРНОЙ СТЕГАНОГРАФИИ ЗАВЕРШЕНО\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

if __name__ == "__main__":
    run_paragraph_steganography()
