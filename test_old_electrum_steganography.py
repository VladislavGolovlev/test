"""
Специализированный высокопроизводительный скрипт тестирования Варианта Б:
«Формат мнемоник Old Electrum (2011–2014)»
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой адрес: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo

Особенности Old Electrum:
- Словарь: 1626 слов из поэтического словаря Contemporary Poetry (Wiktionary).
- Длина мнемоники: 12 слов.
- Без контрольной суммы (любые 12 слов из 1626 декодируются в 16-байтный сид).
- Растяжение ключа: 100,000 раундов SHA-256.
- Деривация адресов:
  - Прямой мастер-ключ: compressed и uncompressed P2PKH.
  - Адрес 0 (change=0, n=0): compressed и uncompressed P2PKH.
  - Адрес 1 (change=0, n=1): compressed и uncompressed P2PKH.
  - Адрес 2 (change=0, n=2): compressed и uncompressed P2PKH.

Тестируемые генераторы мнемоник:
1. Слайдинг-окна (Sliding Windows) шагом 1 по рассказу Revolution и всей статье.
2. Прореживание шагами k in [2..15] с различными смещениями.
3. GPS-метод автора (di + step * i) по локациям: Циндао, Тайвань, Верховный суд, Шпонхайм и др.
4. Телефонный метод автора (индексы Eric & Carl) и числа рассказа Revolution.
5. Структурные срезы (1-е, 2-е, последнее слово каждого предложения и абзаца).
"""

import sys
import os
import time
import re
import hashlib
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
WORDS_FILE = BASE_DIR / "electrum_words.txt"
PROGRESS_FILE = BASE_DIR / "progress_electrum.txt"
CANDIDATES_FILE = BASE_DIR / "valid_electrum_candidates.txt"
FOUND_FILE = BASE_DIR / "FOUND_SOLUTION.txt"

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]
SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
NUM_THREADS = os.cpu_count() or 8

# Загрузка словаря Old Electrum (1626 слов)
with open(WORDS_FILE, "r", encoding="utf-8") as f:
    wordlist = [w.strip().lower() for w in f if w.strip()]
assert len(wordlist) == 1626
word_to_idx = {w: i for i, w in enumerate(wordlist)}
electrum_set = set(wordlist)
N_DICT = len(wordlist)

def mn_decode(wlist: list[str]) -> str | None:
    """Декодирует 12 слов старого формата Electrum в 32-символьный hex-сид."""
    if len(wlist) != 12:
        return None
    out = ""
    for i in range(4):
        w1_str, w2_str, w3_str = wlist[3 * i : 3 * i + 3]
        if w1_str not in word_to_idx or w2_str not in word_to_idx or w3_str not in word_to_idx:
            return None
        w1 = word_to_idx[w1_str]
        w2 = word_to_idx[w2_str] % N_DICT
        w3 = word_to_idx[w3_str] % N_DICT
        x = w1 + N_DICT * ((w2 - w1) % N_DICT) + N_DICT * N_DICT * ((w3 - w2) % N_DICT)
        out += "%08x" % x
    return out

def stretch_key(hex_seed: str) -> int:
    """100,000 раундов SHA-256 для вычисления секретной экспоненты Electrum."""
    encoded = hex_seed.encode("ascii")
    x = encoded
    for _ in range(100000):
        x = hashlib.sha256(x + encoded).digest()
    return int.from_bytes(x, "big") % SECP256K1_ORDER

def check_seed_electrum(hex_seed: str):
    """
    Проверяет сид по алгоритму Old Electrum:
    - Master key (compressed & uncompressed)
    - change=0, n=0..2 (compressed & uncompressed)
    """
    secexp = stretch_key(hex_seed)

    # 1. Прямой мастер-ключ
    master_priv = coincurve.PrivateKey(secexp.to_bytes(32, "big"))
    for comp in (True, False):
        pub = master_priv.public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "master_key", comp

    # Мастер-публичный ключ (uncompressed 64 байта без 04)
    pub_master_unc = master_priv.public_key.format(compressed=False)
    mpk_bytes = pub_master_unc[1:]

    # 2. Адреса для change=0, n=0, 1, 2
    for n in (0, 1, 2):
        msg = f"{n}:0:".encode("ascii") + mpk_bytes
        h1 = hashlib.sha256(msg).digest()
        h2 = hashlib.sha256(h1).digest()
        z = int.from_bytes(h2, "big")

        priv_n = (secexp + z) % SECP256K1_ORDER
        priv_addr = coincurve.PrivateKey(priv_n.to_bytes(32, "big"))
        for comp in (True, False):
            pub_n = priv_addr.public_key.format(compressed=comp)
            if hashlib.new("ripemd160", hashlib.sha256(pub_n).digest()).digest() == TARGET_H160:
                return f"electrum_0_{n}", comp

    return None

def check_phrase_worker(item: tuple[str, str]):
    phrase, meta = item
    words = phrase.strip().split()
    hex_seed = mn_decode(words)
    if not hex_seed:
        return None
    match = check_seed_electrum(hex_seed)
    if match:
        path, comp = match
        return phrase, hex_seed, path, comp, meta
    return None

class Evaluator:
    def __init__(self):
        self.seen_mnemonics = set()
        self.total_checked = 0
        self.start_time = time.time()
        self.last_report = time.time()
        self.candidates_buffer = []

    def update_progress_file(self, pct: float, current: int, total: int, speed: float, el_str: str, eta_str: str, phase_name: str):
        try:
            with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
                f.write("======================================================================\n")
                f.write(" МОНИТОРИНГ OLD ELECTRUM (2011-2014) СТЕГАНОГРАФИИ\n")
                f.write("======================================================================\n")
                f.write(f"Текущая фаза:     {phase_name}\n")
                f.write(f"Прогресс фазы:    {pct:.1f}% ({current:,} / {total:,})\n")
                f.write(f"Скорость:         {speed:,.1f} сид/сек\n")
                f.write(f"Прошедшее время:  {el_str}\n")
                f.write(f"Осталось (ETA):   {eta_str}\n")
                f.write(f"Всего проверено:  {self.total_checked:,}\n")
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

        if len(self.candidates_buffer) >= 20:
            with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
                f.writelines(self.candidates_buffer)
            self.candidates_buffer.clear()

        batch_size = 200
        total_items = len(unique_items)
        processed = 0
        t_phase_start = time.time()

        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            for i in range(0, total_items, batch_size):
                chunk = unique_items[i : i + batch_size]
                results = list(executor.map(check_phrase_worker, chunk))
                for res in results:
                    if res:
                        phrase, hex_seed, path, comp, meta = res
                        addr = base58.b58encode_check(b"\x00" + TARGET_H160).decode()
                        print("\n" + "!" * 75, flush=True)
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ (OLD ELECTRUM)!", flush=True)
                        print(f"Адрес:        {addr}", flush=True)
                        print(f"Мнемоника:    {phrase}", flush=True)
                        print(f"Hex-сид:      {hex_seed}", flush=True)
                        print(f"Путь:         {path} (compressed={comp})", flush=True)
                        print(f"Метаданные:   {meta}", flush=True)
                        print("!" * 75, flush=True)
                        with open(FOUND_FILE, "w", encoding="utf-8") as f:
                            f.write(f"ADDRESS: {addr}\nMNEMONIC: {phrase}\nHEX_SEED: {hex_seed}\nPATH: {path}\nCOMP: {comp}\nMETA: {meta}\n")
                        return True

                processed += len(chunk)
                self.total_checked += len(chunk)
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

def run_old_electrum_tests():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА Б: ФОРМАТ МНЕМОНИК OLD ELECTRUM (2011-2014)")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print(f"Словарь:        1626 слов Contemporary Poetry")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ OLD ELECTRUM ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    tokens_all = clean_tokens(full_text)
    electrum_chain_all = [w for w in tokens_all if w in electrum_set]

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]
    rev_text = " ".join(paragraphs[2:11])
    tokens_rev = clean_tokens(rev_text)
    electrum_chain_rev = [w for w in tokens_rev if w in electrum_set]

    print(f"Слов Electrum во всей статье: {len(electrum_chain_all)} (уникальных: {len(set(electrum_chain_all))})")
    print(f"Слов Electrum в Revolution:   {len(electrum_chain_rev)} (уникальных: {len(set(electrum_chain_rev))})")

    # =========================================================================
    # ГЕНЕРАТОР 1: Слайдинг-окна (Sliding Windows) шагом 1
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ГЕНЕРАТОР 1]: Слайдинг-окна шагом 1 по тексту...", flush=True)

    cands_g1 = []
    # По рассказу Revolution
    for s in range(len(electrum_chain_rev) - 11):
        cands_g1.append((" ".join(electrum_chain_rev[s : s + 12]), f"Слайдинг Revolution (старт {s})"))

    # По всей статье
    for s in range(len(electrum_chain_all) - 11):
        cands_g1.append((" ".join(electrum_chain_all[s : s + 12]), f"Слайдинг Вся статья (старт {s})"))

    print(f"  Сформировано слайдинг-кандидатов: {len(cands_g1)}")
    if evaluator.evaluate_phrases(cands_g1, "Генератор 1: Слайдинг-окна"):
        return

    # =========================================================================
    # ГЕНЕРАТОР 2: Прореживание шагами k in [2..15] с различными смещениями
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ГЕНЕРАТОР 2]: Периодические шаги k in [2..15]...", flush=True)

    cands_g2 = []
    # По Revolution
    for k in range(2, 10):
        for offset in range(k):
            seq = electrum_chain_rev[offset::k]
            if len(seq) >= 12:
                for s in range(len(seq) - 11):
                    cands_g2.append((" ".join(seq[s : s + 12]), f"Шаг {k} Revolution (смещ {offset}, старт {s})"))

    # По всей статье
    for k in range(2, 20):
        for offset in range(k):
            seq = electrum_chain_all[offset::k]
            if len(seq) >= 12:
                for s in range(len(seq) - 11):
                    cands_g2.append((" ".join(seq[s : s + 12]), f"Шаг {k} Вся статья (смещ {offset}, старт {s})"))

    print(f"  Сформировано периодических кандидатов: {len(cands_g2)}")
    if evaluator.evaluate_phrases(cands_g2, "Генератор 2: Периодические шаги"):
        return

    # =========================================================================
    # ГЕНЕРАТОР 3: GPS-метод автора по ключевым локациям
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ГЕНЕРАТОР 3]: GPS-метод автора (d_i + step * i) по локациям...", flush=True)

    locations = {
        # Циндао (город, вокзал, пирс, порт)
        "Qingdao_City": "360671120382",
        "Qingdao_Port": "360814120311",
        "Qingdao_Pier": "360583120312",
        "Qingdao_Station": "360639120313",
        # Тайвань (Цзилун, Тайбэй)
        "Keelung_Port": "251344121743",
        "Taipei_City": "250330121565",
        # Верховный суд (авторский пример)
        "Supreme_Court": "388906770044",
        # Маунт-Вернон (Вашингтон)
        "Mount_Vernon": "387081770861",
        # Тритемий (Шпонхайм, Вюрцбург, Триттенхайм)
        "Sponheim": "498457077250",
        "Trittenheim": "498258069006",
        "Wuerzburg": "497956099206",
        # Оксфорд
        "Oxford_Jesus": "517534012569",
        # Каракас
        "Caracas": "104806669036",
    }

    cands_g3 = []
    N_rev = len(electrum_chain_rev)

    for loc_name, coords in locations.items():
        digits_12 = [int(c) for c in coords]
        for step in [10, 9, 8, 11, 7, 12]:
            for shift in range(-3, 4):
                idxs = [(d + step * i + shift) for i, d in enumerate(digits_12)]
                # Linear bound check
                if all(0 <= idx < N_rev for idx in idxs):
                    phrase = [electrum_chain_rev[idx] for idx in idxs]
                    cands_g3.append((" ".join(phrase), f"GPS {loc_name} (step={step}, shift={shift})"))
                # Modulo check
                idxs_mod = [(d + step * i + shift) % N_rev for i, d in enumerate(digits_12)]
                phrase_mod = [electrum_chain_rev[idx] for idx in idxs_mod]
                cands_g3.append((" ".join(phrase_mod), f"GPS {loc_name} modulo (step={step}, shift={shift})"))

    print(f"  Сформировано GPS-кандидатов Electrum: {len(cands_g3)}")
    if evaluator.evaluate_phrases(cands_g3, "Генератор 3: GPS-метод"):
        return

    # =========================================================================
    # ГЕНЕРАТОР 4: Телефонные индексы Eric & Carl и числа рассказа
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ГЕНЕРАТОР 4]: Телефонные индексы и числа рассказа...", flush=True)

    author_phone_idxs = [2, 6, 9, 18, 22, 25, 45, 70, 86, 100, 113, 116]
    nums_12 = [1930, 2000, 1920, 6, 40, 40, 10, 18, 5, 221, 206, 50]

    cands_g4 = []
    for shift in range(-6, 7):
        # Телефоны (0-based и 1-based)
        idxs_phone = [(idx + shift - 1) % N_rev for idx in author_phone_idxs]
        cands_g4.append((" ".join([electrum_chain_rev[i] for i in idxs_phone]), f"Телефоны Electrum (shift={shift})"))

        # Числа рассказа % N_rev
        idxs_nums = [(n + shift) % N_rev for n in nums_12]
        cands_g4.append((" ".join([electrum_chain_rev[i] for i in idxs_nums]), f"Числа рассказа Electrum % N (shift={shift})"))

        # Последние 2 цифры чисел
        last2 = [(n % 100 + shift) % N_rev for n in nums_12]
        cands_g4.append((" ".join([electrum_chain_rev[i] for i in last2]), f"Посл. 2 цифры чисел Electrum (shift={shift})"))

    print(f"  Сформировано телефонно-числовых кандидатов: {len(cands_g4)}")
    if evaluator.evaluate_phrases(cands_g4, "Генератор 4: Телефоны и числа"):
        return

    # =========================================================================
    # ГЕНЕРАТОР 5: Структурные срезы (предложения и абзацы)
    # =========================================================================
    print("\n" + "=" * 75, flush=True)
    print("[ГЕНЕРАТОР 5]: Предложения и абзацы Electrum...", flush=True)

    raw_sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', rev_text) if s.strip()]
    sent_electrum = []
    for s in raw_sentences:
        toks = clean_tokens(s)
        el = [w for w in toks if w in electrum_set]
        if el:
            sent_electrum.append(el)

    cands_g5 = []
    if len(sent_electrum) >= 12:
        for label, fn in [
            ("1-е слово", lambda s: s[0]),
            ("2-е слово", lambda s: s[1] if len(s)>=2 else s[0]),
            ("Посл. слово", lambda s: s[-1]),
        ]:
            # Первые 12 предложений
            p12 = [fn(s) for s in sent_electrum[:12]]
            cands_g5.append((" ".join(p12), f"Предложения 1..12 Electrum: {label}"))
            # Последние 12 предложений
            plast12 = [fn(s) for s in sent_electrum[-12:]]
            cands_g5.append((" ".join(plast12), f"Предложения посл. 12 Electrum: {label}"))

    print(f"  Сформировано структурных кандидатов: {len(cands_g5)}")
    if evaluator.evaluate_phrases(cands_g5, "Генератор 5: Структурные срезы"):
        return

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ OLD ELECTRUM ЗАВЕРШЕНО", flush=True)
    print(f"Всего проверено мнемоник:   {evaluator.total_checked:,}", flush=True)
    print(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)", flush=True)
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ OLD ELECTRUM ЗАВЕРШЕНО\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено мнемоник:   {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)\n")
        f.write("======================================================================\n")

if __name__ == "__main__":
    run_old_electrum_tests()
