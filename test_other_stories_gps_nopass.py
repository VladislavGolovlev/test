"""
Специализированный высокопроизводительный скрипт тестирования Варианта В:
«GPS-стеганография по другим разделам статьи (БЕЗ ПАРОЛЯ)»
по тексту статьи «Securing Wealth in Poetry» (Trithemian Seeds).

Целевой адрес: 1K4ezpLybootYF23TM4a8Y4NyP7auysnRo

Условия пользователя:
1. Проверка СТРОГО БЕЗ ПАРОЛЯ (passphrase = "").
2. Проверка по всем требуемым путям:
   - Мастер-ключ 'm' (сжатый и несжатый)
   - BIP-44: m/44'/0'/0'/0/0..2 и m/44'/0'/0'/0 (сжатый и несжатый)
   - Legacy: m/0'/0'/0' (сжатый и несжатый)
   - Electrum: m/0/0 и m/0 (сжатый и несжатый)

Тестируемые разделы и географические координаты:
1. Раздел «Steganography»:
   - George Washington / invisible ink: Mount Vernon (387081, 770861 и вариации)
   - Johannes Trithemius: Sponheim (498457, 077250 / 772500), Trittenheim (498258, 069006 / 690060), Würzburg (497956, 099206 / 992060)
   - Oxford: Jesus College (517534, 012569 / 125690), Bodleian Library (517539, 012544 / 125440)
2. Раздел «Fiat»:
   - Dan Mason / Venezuelan Bolivar: Caracas (104806, 669036), Banco Central (105067, 669147), Casa de Moneda (102469, 675958)
3. Разделы «Bitcoin» и «Touchpoints»:
   - SatoshiLabs Prague (500755, 144378), Zug Switzerland (471662, 085155), Washington DC (388977, 770365), Supreme Court (388906, 770044)
4. Связка «From China to Zimbabwe to present day Venezuela»:
   - Harare (178248, 310530), Zimbabwe center (190154, 291549) + Caracas (104806, 669036)
5. Кросс-маршруты и смешанные координаты.
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
PROGRESS_FILE = BASE_DIR / "progress_stories_nopass.txt"
CANDIDATES_FILE = BASE_DIR / "valid_stories_nopass_candidates.txt"
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
                f.write(" МОНИТОРИНГ GPS ДРУГИХ ГЛАВ (СТРОГО БЕЗ ПАРОЛЯ)\n")
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
                        print("🎉🎉🎉 УРА! НАЙДЕНО РЕШЕНИЕ ГОЛОВОЛОМКИ (GPS ДРУГИХ ГЛАВ)!", flush=True)
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

# Географические координаты
LOCATIONS = {
    # 1. Steganography: Washington / Mount Vernon
    "Mount_Vernon_1": "387081770861",
    "Mount_Vernon_2": "387080770860",
    "Mount_Vernon_3": "387085770865",
    "Mount_Vernon_Rev": "770861387081",
    # 2. Steganography: Johannes Trithemius
    "Sponheim_1": "498457077250",
    "Sponheim_2": "498457772500",
    "Trittenheim_1": "498258069006",
    "Trittenheim_2": "498258690060",
    "Wuerzburg_1": "497956099206",
    "Wuerzburg_2": "497956992060",
    # 3. Steganography: Oxford
    "Oxford_Jesus_1": "517534012569",
    "Oxford_Jesus_2": "517534125690",
    "Oxford_Bodleian_1": "517539012544",
    "Oxford_Bodleian_2": "517539125440",
    # 4. Fiat: Dan Mason / Venezuela
    "Caracas_1": "104806669036",
    "Caracas_Rev": "669036104806",
    "Banco_Central_Ven": "105067669147",
    "Casa_Moneda_Ven": "102469675958",
    # 5. Bitcoin / Touchpoints:
    "SatoshiLabs_Prague": "500755144378",
    "Zug_Crypto_Valley": "471662085155",
    "Washington_DC": "388977770365",
    "Supreme_Court": "388906770044",
    # 6. China to Zimbabwe to Venezuela
    "Harare_Zimbabwe": "178248310530",
    "Zimbabwe_Center": "190154291549",
    "Zim_Ven_Combo_1": "178248104806",
    "Zim_Ven_Combo_2": "310530669036",
    "Zim_Ven_Combo_3": "178248669036",
    "Sponheim_Oxford_Combo": "498457517534",
    "Washington_Caracas_Combo": "387081104806",
    # 7. China / Taiwan migration:
    "Qingdao_City": "360671120382",
    "Qingdao_Port": "360814120311",
    "Qingdao_Pier": "360583120312",
    "Qingdao_Station": "360639120313",
    "Keelung_Port": "251344121743",
    "Taipei_City": "250330121565",
    "Qingdao_Keelung_Combo": "360671251344",
    "Qingdao_Port_Keelung": "360814121743",
}

def run_other_stories_tests():
    evaluator = Evaluator()
    print("=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ ВАРИАНТА В: GPS ДРУГИХ ГЛАВ (СТРОГО БЕЗ ПАРОЛЯ)")
    print(f"Целевой адрес:  {TARGET_ADDRESS}")
    print("Пароль:         '' (ПУСТОЙ)")
    print(f"Потоков CPU:    {NUM_THREADS}")
    print("=" * 75, flush=True)

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("--- НАЧАЛО ТЕСТИРОВАНИЯ GPS ДРУГИХ ГЛАВ (БЕЗ ПАРОЛЯ) ---\n")

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        full_text = f.read()

    paragraphs = [p.strip() for p in full_text.split("\n\n") if p.strip()]

    # Главы и рассказы статьи:
    chapters = {
        "Steganography": " ".join(paragraphs[28:36]),
        "Fiat": " ".join(paragraphs[11:14]),
        "Bitcoin": " ".join(paragraphs[14:19]),
        "Touchpoints": " ".join(paragraphs[19:27]),
        "Trithemian_Seeds": " ".join(paragraphs[36:39]),
        "Revolution": " ".join(paragraphs[2:11]),
        "Phone_Story": paragraphs[40] if len(paragraphs) > 40 else "",
        "GPS_Story": paragraphs[42] if len(paragraphs) > 42 else "",
        "Full_Article": full_text,
    }

    for ch_name, ch_text in chapters.items():
        toks = clean_tokens(ch_text)
        bips = [w for w in toks if w in bip_set]
        print(f"Глава {ch_name:<18}: всего слов {len(toks):3d}, BIP-39 слов: {len(bips):3d}")

    # Генератор комбинаций для главы
    def gen_gps_for_chapter(ch_name, words_list, is_bip_only):
        N = len(words_list)
        if N < 12:
            return
        base_step = round(N / 12)
        candidate_steps = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 25, 30, 35, 40, 45, 48, 50,
                           base_step, base_step - 2, base_step - 1, base_step + 1, base_step + 2]
        steps = sorted(list(set(candidate_steps)))
        steps = [s for s in steps if s > 0]

        for loc_name, coords in LOCATIONS.items():
            digits_12 = [int(c) for c in coords]
            for step in steps:
                for off in range(-5, 6):
                    for mult in (0, 1):
                        # Линейный режим
                        idxs_lin = [(mult * d + step * i + off) for i, d in enumerate(digits_12)]
                        if all(0 <= idx < N for idx in idxs_lin):
                            phrase = [words_list[idx] for idx in idxs_lin]
                            if all(w in bip_set for w in phrase):
                                yield phrase, f"{ch_name} (лин) | {loc_name} (step={step}, off={off})"

                        # Модуло режим
                        idxs_mod = [(mult * d + step * i + off) % N for i, d in enumerate(digits_12)]
                        phrase_m = [words_list[idx] for idx in idxs_mod]
                        if all(w in bip_set for w in phrase_m):
                            # Исключаем вырожденные фразы (слишком много повторов)
                            counts = Counter(phrase_m)
                            if max(counts.values()) <= 2:
                                yield phrase_m, f"{ch_name} (mod) | {loc_name} (step={step}, off={off})"

    # Тестируем по каждой главе
    for ch_name, ch_text in chapters.items():
        toks = clean_tokens(ch_text)
        bips = [w for w in toks if w in bip_set]

        # 1. По цепочке BIP-слов главы
        evaluator.test_combinations_stream(
            gen_gps_for_chapter(ch_name, bips, is_bip_only=True),
            50000,
            f"GPS по BIP-цепочке главы «{ch_name}»"
        )

        # 2. По общему потоку слов главы
        evaluator.test_combinations_stream(
            gen_gps_for_chapter(ch_name, toks, is_bip_only=False),
            50000,
            f"GPS по потоку слов главы «{ch_name}»"
        )

    evaluator.flush_candidates()
    elapsed = time.time() - evaluator.start_time
    print("\n" + "=" * 75, flush=True)
    print("ИССЛЕДОВАНИЕ GPS ДРУГИХ ГЛАВ ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)", flush=True)
    print(f"Всего проверено комбинаций: {evaluator.total_checked:,}", flush=True)
    print(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)", flush=True)
    print(f"Валидных чексумм найдено:   {evaluator.valid_checksums:,}", flush=True)
    print(f"Уникальных сидов проверено: {evaluator.unique_seeds:,}", flush=True)
    print("=" * 75, flush=True)

    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write(" ИССЛЕДОВАНИЕ GPS ДРУГИХ ГЛАВ ЗАВЕРШЕНО (БЕЗ ПАРОЛЯ)\n")
        f.write("======================================================================\n")
        f.write("Статус:                     ЗАВЕРШЕНО (Совпадений с целевым адресом нет)\n")
        f.write(f"Всего проверено комбинаций: {evaluator.total_checked:,}\n")
        f.write(f"Затрачено времени:          {elapsed:.2f} сек ({elapsed/60:.1f} мин)\n")
        f.write(f"Валидных чексумм:           {evaluator.valid_checksums:,}\n")
        f.write(f"Уникальных сидов:           {evaluator.unique_seeds:,}\n")
        f.write("======================================================================\n")

if __name__ == "__main__":
    run_other_stories_tests()
