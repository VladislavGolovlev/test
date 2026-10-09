"""
Специализированный скрипт тестирования гипотезы сокрытия сид-фразы в других разделах статьи
«Securing Wealth in Poetry» (Trithemian Seeds).

Версия 2.2 (Оптимальная и исчерпывающая):
1. Разделы статьи:
   - «Steganography»:
     - George Washington & invisible inks: Mount Vernon (387081, 770861 и вариации)
     - Johannes Trithemius: Sponheim (498457, 077250 / 772500), Trittenheim (498258, 069006 / 690060), Würzburg (497956, 099206 / 992060)
     - Oxford: Jesus College (517534, 012569 / 125690), Bodleian Library (517539, 012544 / 125440)
   - «Fiat»:
     - Venezuela / bolivars («Courtesy of Dan Mason»): Caracas (104806, 669036), Banco Central (105067, 669147), Casa de Moneda (102469, 675958)
   - «Bitcoin» и «Touchpoints»:
     - SatoshiLabs Прага (500755, 144378), Zug (471662, 085155), London (515155, 011077), Washington DC (388977, 770365)
     - Авторский пример Supreme Court (388906, 770044)
     - Кросс-маршруты и даты статьи.
2. Алгоритмы индексации:
   - Стандартные шаги автора: 10, 9, 11, 8, 12.
   - Масштабированные шаги: base = round(N/12) +/- 1..3 для адаптации линейного режима к длине списков.
   - Смещения off: -3..+3, множители m in {0, 1}.
   - 1-based и 0-based индексация.
   - Линейный режим (Linear bounds) и циклический (Modulo).
   - Тестирование как по BIP-39 цепочкам, так и по общему потоку слов (word flow).
3. Криптография и деривация:
   - СТРОГО мастер-ключ 'm' (BIP-32 напрямую без субдеривации) compressed & uncompressed.
   - BIP-44: m/44'/0'/0'/0/0..2, m/44'/0'/0'/0, m/44'/0'/0'.
   - Legacy: m/0'/0'/0', m/0'/0'/0'/0/0, m/0, m/0/0, m/0/0/0.
   - Быстрая проверка coincurve (libsecp256k1).
   - Исчерпывающий список паролей (ТЗ + вариации).
4. Оптимизация:
   - Асинхронная проверка паролей в пуле потоков.
   - Фильтрация вырожденных повторов слов при modulo (>=3 повторов одного слова).
5. Мониторинг:
   - Консоль с flush=True (процент, скорость, ETA, валидные, проверено).
   - Запись прогресса в progress_stories.txt.
   - Сохранение валидных кандидатов в valid_stories_candidates.txt.
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

# =====================================================================
# Конфигурация и пути
# =====================================================================
BASE_DIR = Path(r"c:\Users\Vladislav\Desktop\Новая папка")
TEXT_FILE = BASE_DIR / "clean_article.txt"
WORDS_FILE = BASE_DIR / "word.txt"
PROGRESS_FILE = BASE_DIR / "progress_stories.txt"
CANDIDATES_FILE = BASE_DIR / "valid_stories_candidates.txt"
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
    "Fiat",
    "fiat",
    "Dan Mason",
    "dan mason",
    "DanMason",
    "danmason",
    "Mount Vernon",
    "mount vernon",
    "MountVernon",
    "mountvernon",
    "M.7.7 Gall.",
    "m.7.7 gall.",
    "M.7.7",
    "m.7.7",
    "sympathetic stain",
    "Sympathetic Stain",
    "sympatheticstain",
    "Steganographia",
    "steganographia",
    "Steganography",
    "steganography",
    "Jesus College",
    "jesus college",
    "JesusCollege",
    "Oxford",
    "oxford",
    "Sponheim",
    "sponheim",
    "Trittenheim",
    "trittenheim",
    "Würzburg",
    "würzburg",
    "Wuerzburg",
    "wuerzburg",
    "Caracas",
    "caracas",
    "Bolivar",
    "bolivar",
    "Bitcoin",
    "bitcoin",
    "Touchpoints",
    "touchpoints",
    "Revolution",
    "revolution",
    "Securing Wealth in Poetry",
]

# =====================================================================
# Криптографические функции (BIP-32 / BIP-44 через coincurve)
# =====================================================================
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
    """
    Проверяет сид против TARGET_H160 по ключевым путям деривации
    (сжатые и несжатые ключи).
    ВКЛЮЧАЕТ ПУТЬ 'm' (мастер-ключ BIP-32 напрямую без субдеривации).
    """
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]

    # 1. СТРОГО: Master key 'm' напрямую (compressed & uncompressed)
    for comp in (True, False):
        pub = coincurve.PrivateKey(master_k).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m", comp

    # 2. BIP-44: m/44'/0'/0'/0/0..2, m/44'/0'/0'/0, m/44'/0'/0'
    k44, c44 = ckd_priv(master_k, master_c, 44 + 0x80000000)
    if k44 is not None:
        k44_0, c44_0 = ckd_priv(k44, c44, 0 + 0x80000000)
        if k44_0 is not None:
            k44_0_0, c44_0_0 = ckd_priv(k44_0, c44_0, 0 + 0x80000000)
            if k44_0_0 is not None:
                for comp in (True, False):
                    pub = coincurve.PrivateKey(k44_0_0).public_key.format(compressed=comp)
                    if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                        return "m/44'/0'/0'", comp

                k44_0_0_0, c44_0_0_0 = ckd_priv(k44_0_0, c44_0_0, 0)
                if k44_0_0_0 is not None:
                    for comp in (True, False):
                        pub = coincurve.PrivateKey(k44_0_0_0).public_key.format(compressed=comp)
                        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                            return "m/44'/0'/0'/0", comp

                    for addr_idx in (0, 1, 2):
                        k_addr, _ = ckd_priv(k44_0_0_0, c44_0_0_0, addr_idx)
                        if k_addr is None:
                            continue
                        for comp in (True, False):
                            pub = coincurve.PrivateKey(k_addr).public_key.format(compressed=comp)
                            if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                                return f"m/44'/0'/0'/0/{addr_idx}", comp

    # 3. m/0'/0'/0' и m/0'/0'/0'/0/0 (BIP-32 legacy)
    k0, c0 = ckd_priv(master_k, master_c, 0 + 0x80000000)
    if k0 is not None:
        k0_0, c0_0 = ckd_priv(k0, c0, 0 + 0x80000000)
        if k0_0 is not None:
            k0_0_0, c0_0_0 = ckd_priv(k0_0, c0_0, 0 + 0x80000000)
            if k0_0_0 is not None:
                for comp in (True, False):
                    pub = coincurve.PrivateKey(k0_0_0).public_key.format(compressed=comp)
                    if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                        return "m/0'/0'/0'", comp

                k0_tree_0, c0_tree_0 = ckd_priv(k0_0_0, c0_0_0, 0)
                if k0_tree_0 is not None:
                    k0_tree_addr, _ = ckd_priv(k0_tree_0, c0_tree_0, 0)
                    if k0_tree_addr is not None:
                        for comp in (True, False):
                            pub = coincurve.PrivateKey(k0_tree_addr).public_key.format(compressed=comp)
                            if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                                return "m/0'/0'/0'/0/0", comp

    # 4. m/0, m/0/0, m/0/0/0 (Electrum / Coinomi legacy)
    km0, cm0 = ckd_priv(master_k, master_c, 0)
    if km0 is not None:
        for comp in (True, False):
            pub = coincurve.PrivateKey(km0).public_key.format(compressed=comp)
            if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                return "m/0", comp

        km0_0, cm0_0 = ckd_priv(km0, cm0, 0)
        if km0_0 is not None:
            for comp in (True, False):
                pub = coincurve.PrivateKey(km0_0).public_key.format(compressed=comp)
                if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                    return "m/0/0", comp

            km0_0_0, _ = ckd_priv(km0_0, cm0_0, 0)
            if km0_0_0 is not None:
                for comp in (True, False):
                    pub = coincurve.PrivateKey(km0_0_0).public_key.format(compressed=comp)
                    if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                        return "m/0/0/0", comp

    return None

def verify_checksum(idxs_12: list[int]) -> bool:
    val = 0
    for idx in idxs_12:
        val = (val << 11) | idx
    entropy = (val >> 4).to_bytes(16, "big")
    expected_cs = hashlib.sha256(entropy).digest()[0] >> 4
    return (val & 0x0F) == expected_cs

# =====================================================================
# Класс отслеживания прогресса (Консоль + Файл progress_stories.txt)
# =====================================================================
class ProgressTracker:
    def __init__(self, total_combos: int, progress_file: Path, update_interval: float = 1.5):
        self.total = total_combos
        self.progress_file = progress_file
        self.update_interval = update_interval
        self.start_time = time.time()
        self.last_update = 0.0
        self.checked = 0
        self.valid_checksums = 0
        self.unique_mnemonics = 0
        self.linear_checksums = 0
        self.current_phase = "Инициализация"
        self.last_valid_mnemonic = ""
        self.found = False

    def set_phase(self, phase_name: str):
        self.current_phase = phase_name
        self.update(force=True)

    def advance(self, count: int = 1):
        self.checked += count
        if self.checked % 5000 == 0:
            now = time.time()
            if now - self.last_update >= self.update_interval:
                self.update_at(now)

    def add_valid(self, mnemonic: str, is_linear: bool = False):
        self.valid_checksums += 1
        if is_linear:
            self.linear_checksums += 1
        self.last_valid_mnemonic = mnemonic

    def add_unique(self):
        self.unique_mnemonics += 1

    def update(self, force: bool = False):
        now = time.time()
        if not force and (now - self.last_update < self.update_interval):
            return
        self.update_at(now)

    def update_at(self, now: float):
        self.last_update = now
        elapsed = now - self.start_time
        speed = self.checked / elapsed if elapsed > 0 else 0.0
        pct = (self.checked / self.total * 100) if self.total > 0 else 0.0
        remaining = max(0, self.total - self.checked)
        eta_sec = remaining / speed if speed > 0 else 0.0

        if eta_sec >= 60:
            eta_str = f"{int(eta_sec // 60)} мин {int(eta_sec % 60):02d} сек"
        else:
            eta_str = f"{eta_sec:.1f} сек"

        status_text = (
            f"[{pct:5.1f}%] Проверено: {self.checked:,} / {self.total:,} | "
            f"Скорость: {speed:,.0f} комб/с | Прошло: {elapsed:.1f}с | ETA: {eta_str} | "
            f"Фаза: {self.current_phase[:30]} | Валидных: {self.valid_checksums} (Linear: {self.linear_checksums}, Уник: {self.unique_mnemonics})"
        )
        print(status_text, flush=True)

        try:
            with open(self.progress_file, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(" СТАТУС ТЕСТИРОВАНИЯ ДРУГИХ РАЗДЕЛОВ СТАТЬИ (GPS STORIES v2.2)\n")
                f.write("=" * 70 + "\n")
                f.write(f"Состояние:        {'НАЙДЕНО РЕШЕНИЕ!' if self.found else 'ВЫПОЛНЯЕТСЯ'}\n")
                f.write(f"Текущая фаза:     {self.current_phase}\n")
                f.write(f"Прогресс:         {pct:.2f}%\n")
                f.write(f"Проверено:        {self.checked:,} из {self.total:,}\n")
                f.write(f"Скорость:         {speed:,.1f} комбинаций/сек\n")
                f.write(f"Время работы:     {elapsed:.1f} сек\n")
                f.write(f"Расчётное ETA:    {eta_str}\n")
                f.write(f"Валидных чексумм: {self.valid_checksums} (Линейных: {self.linear_checksums})\n")
                f.write(f"Уникальных сидов: {self.unique_mnemonics}\n")
                if self.last_valid_mnemonic:
                    f.write(f"Последний валидный кандидат:\n  {self.last_valid_mnemonic}\n")
                f.write("=" * 70 + "\n")
                f.flush()
        except Exception:
            pass

    def finish(self, found_details: str = ""):
        self.found = bool(found_details)
        now = time.time()
        elapsed = now - self.start_time
        speed = self.checked / elapsed if elapsed > 0 else 0.0

        print("\n" + "=" * 70, flush=True)
        print(f"ТЕСТИРОВАНИЕ ЗАВЕРШЕНО за {elapsed:.2f} сек!", flush=True)
        print(f"Всего проверено: {self.checked:,} комбинаций ({speed:,.0f} комб/с)", flush=True)
        print(f"Найдено валидных BIP-39 чексумм: {self.valid_checksums} (Линейных: {self.linear_checksums}, уникальных мнемоник: {self.unique_mnemonics})", flush=True)
        if found_details:
            print("🎉🎉🎉 НАЙДЕНО СОВПАДЕНИЕ С ЦЕЛЕВЫМ КОШЕЛЬКОМ! 🎉🎉🎉", flush=True)
            print(found_details, flush=True)
        print("=" * 70 + "\n", flush=True)

        try:
            with open(self.progress_file, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(" ТЕСТИРОВАНИЕ ДРУГИХ РАЗДЕЛОВ СТАТЬИ ЗАВЕРШЕНО (v2.2)\n")
                f.write("=" * 70 + "\n")
                f.write(f"Статус:           {'УСПЕХ! ЦЕЛЕВОЙ АДРЕС НАЙДЕН' if self.found else 'ЗАВЕРШЕНО (Совпадений с адресом нет)'}\n")
                f.write(f"Всего проверено:  {self.checked:,} комбинаций\n")
                f.write(f"Затрачено времени:{elapsed:.2f} сек\n")
                f.write(f"Средняя скорость: {speed:,.1f} комб/с\n")
                f.write(f"Валидных чексумм: {self.valid_checksums} (Линейных: {self.linear_checksums})\n")
                f.write(f"Уникальных сидов: {self.unique_mnemonics}\n")
                if found_details:
                    f.write("\nДЕТАЛИ НАЙДЕННОГО КОШЕЛЬКА:\n" + found_details + "\n")
                f.write("=" * 70 + "\n")
                f.flush()
        except Exception:
            pass

# =====================================================================
# Оценщик мнемоник с дедупликацией и асинхронным пулом воркеров
# =====================================================================
class CandidateEvaluator:
    def __init__(self, word_to_idx: dict[str, int], tracker: ProgressTracker, candidates_file: Path, passphrases: list[str]):
        self.word_to_idx = word_to_idx
        self.tracker = tracker
        self.candidates_file = candidates_file
        self.passphrases = passphrases
        self.other_pws = [pw for pw in passphrases if pw != ""]
        self.seen_mnemonics = set()
        self.out_f = open(candidates_file, "a", encoding="utf-8")
        self.out_buffer = []
        self.found = False
        self.found_details = ""
        self.pool = ThreadPoolExecutor(max_workers=8)
        self.pending_futures = []

    def _eval_one(self, mnemonic: str, pw: str):
        salt = ("mnemonic" + pw).encode("utf-8")
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048)
        match = check_seed_fast(seed)
        if match:
            return pw, match
        return None

    def _eval_worker(self, mnemonic: str, desc: str):
        if self.found:
            return
        for pw in self.other_pws:
            salt = ("mnemonic" + pw).encode("utf-8")
            seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048)
            match = check_seed_fast(seed)
            if match:
                path, comp = match
                details = (
                    f"Фраза:    {mnemonic}\n"
                    f"Пароль:   '{pw}'\n"
                    f"Путь:     {path} (compressed={comp})\n"
                    f"Адрес:    {TARGET_ADDRESS}\n"
                    f"Алгоритм: {desc}\n"
                )
                self.found = True
                self.found_details = details
                with open(FOUND_FILE, "w", encoding="utf-8") as f_out:
                    f_out.write(details)
                self.tracker.finish(details)
                return

    def evaluate(self, words_12: list[str], desc: str, is_linear: bool = False) -> bool:
        if self.found:
            return True

        # Проверка на вырожденные дубликаты (в настоящих мнемониках не бывает >= 3 одинаковых слов)
        counts = Counter(words_12)
        if any(c >= 3 for c in counts.values()):
            return False

        idxs = [self.word_to_idx.get(w.lower()) for w in words_12]
        if any(i is None for i in idxs):
            return False

        if not verify_checksum(idxs):
            return False

        mnemonic = " ".join(words_12)
        self.tracker.add_valid(mnemonic, is_linear=is_linear)

        if mnemonic in self.seen_mnemonics:
            return False
        self.seen_mnemonics.add(mnemonic)
        self.tracker.add_unique()

        self.out_buffer.append(f"{mnemonic} | {desc}\n")
        if len(self.out_buffer) >= 20:
            self.out_f.writelines(self.out_buffer)
            self.out_f.flush()
            self.out_buffer.clear()

        # 1. Быстрая проверка пустого пароля (стандарт BIP-39)
        res_empty = self._eval_one(mnemonic, "")
        if res_empty:
            pw, match = res_empty
            path, comp = match
            details = (
                f"Фраза:    {mnemonic}\n"
                f"Пароль:   '' (пустой)\n"
                f"Путь:     {path} (compressed={comp})\n"
                f"Адрес:    {TARGET_ADDRESS}\n"
                f"Алгоритм: {desc}\n"
            )
            self.found = True
            self.found_details = details
            with open(FOUND_FILE, "w", encoding="utf-8") as f_out:
                f_out.write(details)
            self.tracker.finish(details)
            return True

        # 2. Асинхронная проверка остальных паролей в пуле
        if self.other_pws:
            fut = self.pool.submit(self._eval_worker, mnemonic, desc)
            self.pending_futures.append(fut)
            if len(self.pending_futures) >= 1000:
                self.pending_futures = [f for f in self.pending_futures if not f.done()]

        return False

    def close(self):
        for f in self.pending_futures:
            try:
                f.result()
            except Exception:
                pass
        if self.out_buffer:
            self.out_f.writelines(self.out_buffer)
            self.out_f.flush()
            self.out_buffer.clear()
        self.out_f.close()
        self.pool.shutdown(wait=True)

# =====================================================================
# База координат для всех историй статьи
# =====================================================================
def generate_stories_digit_sequences():
    raw_coords = [
        # --- 1. Mount Vernon (George Washington & sympathetic stain) ---
        ("Mount Vernon (38.7081 N, 77.0861 W)", "387081", "770861"),
        ("Mount Vernon Lon+Lat", "770861", "387081"),
        ("Mount Vernon v2 (38.7080, 77.0862)", "387080", "770862"),
        ("Mount Vernon v2 Lon+Lat", "770862", "387080"),
        ("Mount Vernon v3 (38.7084, 77.0858)", "387084", "770858"),
        ("Mount Vernon v3 Lon+Lat", "770858", "387084"),

        # --- 2. Иоганн Тритемий: Аббатство Шпонхайм ---
        ("Sponheim Abbey (49.8457 N, 07.7250 E)", "498457", "077250"),
        ("Sponheim Abbey Lon+Lat (07.7250)", "077250", "498457"),
        ("Sponheim Abbey pad (49.8457, 7.72500)", "498457", "772500"),
        ("Sponheim Abbey pad Lon+Lat", "772500", "498457"),
        ("Sponheim Abbey v2 (49.8458, 07.7253)", "498458", "077253"),
        ("Sponheim Abbey v2 Lon+Lat", "077253", "498458"),

        # --- 3. Иоганн Тритемий: Триттенхайм (родина) ---
        ("Trittenheim (49.8258 N, 06.9006 E)", "498258", "069006"),
        ("Trittenheim Lon+Lat (06.9006)", "069006", "498258"),
        ("Trittenheim pad (49.8258, 6.90060)", "498258", "690060"),
        ("Trittenheim pad Lon+Lat", "690060", "498258"),
        ("Trittenheim v2 (49.8256, 06.9004)", "498256", "069004"),
        ("Trittenheim v2 Lon+Lat", "069004", "498256"),

        # --- 4. Иоганн Тритемий: Вюрцбург (аббатство Св. Иакова / смерть) ---
        ("Würzburg (49.7956 N, 09.9206 E)", "497956", "099206"),
        ("Würzburg Lon+Lat (09.9206)", "099206", "497956"),
        ("Würzburg pad (49.7956, 9.92060)", "497956", "992060"),
        ("Würzburg pad Lon+Lat", "992060", "497956"),
        ("Würzburg St. James Schottenkloster", "497939", "099512"),
        ("Würzburg St. James Lon+Lat", "099512", "497939"),

        # --- 5. Оксфорд: Jesus College (Fellows' Library M.7.7 Gall.) ---
        ("Oxford Jesus College (51.7534 N, 01.2569 W)", "517534", "012569"),
        ("Oxford Jesus College Lon+Lat (01.2569)", "012569", "517534"),
        ("Oxford Jesus College pad (51.7534, 1.25690)", "517534", "125690"),
        ("Oxford Jesus College pad Lon+Lat", "125690", "517534"),
        ("Oxford Jesus College v2 (51.7535, 01.2570)", "517535", "012570"),
        ("Oxford Jesus College v2 Lon+Lat", "012570", "517535"),

        # --- 6. Оксфорд: Bodleian Library ---
        ("Oxford Bodleian (51.7539 N, 01.2544 W)", "517539", "012544"),
        ("Oxford Bodleian Lon+Lat (01.2544)", "012544", "517539"),
        ("Oxford Bodleian pad (51.7539, 1.25440)", "517539", "125440"),
        ("Oxford Bodleian pad Lon+Lat", "125440", "517539"),

        # --- 7. Каракас, Венесуэла (Dan Mason / Bolivar) ---
        ("Caracas (10.4806 N, 66.9036 W)", "104806", "669036"),
        ("Caracas Lon+Lat", "669036", "104806"),
        ("Caracas Banco Central (10.5067, 66.9147)", "105067", "669147"),
        ("Caracas Banco Central Lon+Lat", "669147", "105067"),
        ("Caracas Casa de Moneda (10.2469, 67.5958)", "102469", "675958"),
        ("Caracas Casa de Moneda Lon+Lat", "675958", "102469"),

        # --- 8. Верховный суд США (авторский пример из статьи) ---
        ("US Supreme Court (38.8906 N, 77.0044 W)", "388906", "770044"),
        ("US Supreme Court Lon+Lat", "770044", "388906"),

        # --- 9. Bitcoin & Touchpoints Landmarks ---
        ("Prague SatoshiLabs Trezor (50.0755, 14.4378)", "500755", "144378"),
        ("Prague SatoshiLabs Lon+Lat", "144378", "500755"),
        ("Zug Crypto Valley (47.1662, 08.5155)", "471662", "085155"),
        ("Zug Crypto Valley Lon+Lat", "085155", "471662"),
        ("London Times Genesis (51.5155, 01.1077)", "515155", "011077"),
        ("London Times Genesis Lon+Lat", "011077", "515155"),
        ("Washington DC (38.8977, 77.0365)", "388977", "770365"),
        ("Washington DC Lon+Lat", "770365", "388977"),
    ]

    cross_pairs = [
        # Маршрут Тритемия (Trittenheim -> Sponheim -> Würzburg)
        ("Маршрут: Trittenheim Lat + Sponheim Lat", "498258", "498457"),
        ("Маршрут: Sponheim Lat + Trittenheim Lat", "498457", "498258"),
        ("Маршрут: Sponheim Lat + Würzburg Lat", "498457", "497956"),
        ("Маршрут: Würzburg Lat + Sponheim Lat", "497956", "498457"),
        ("Маршрут: Trittenheim Lon + Sponheim Lon", "069006", "077250"),
        ("Маршрут: Sponheim Lon + Würzburg Lon", "077250", "099206"),

        # Оксфорд (Jesus College + Bodleian)
        ("Оксфорд: Jesus College Lat + Bodleian Lat", "517534", "517539"),
        ("Оксфорд: Bodleian Lat + Jesus College Lat", "517539", "517534"),
        ("Оксфорд: Jesus College Lon + Bodleian Lon", "012569", "012544"),
        ("Оксфорд: Bodleian Lon + Jesus College Lon", "012544", "012569"),
        ("Оксфорд: Jesus College Lon pad + Bodleian Lon pad", "125690", "125440"),

        # Mount Vernon + Caracas / Supreme Court
        ("Маршрут: Mount Vernon Lat + Caracas Lat", "387081", "104806"),
        ("Маршрут: Caracas Lat + Mount Vernon Lat", "104806", "387081"),
        ("Маршрут: Mount Vernon Lon + Caracas Lon", "770861", "669036"),
        ("Маршрут: Caracas Lon + Mount Vernon Lon", "669036", "770861"),
        ("Маршрут: Mount Vernon Lat + Supreme Court Lat", "387081", "388906"),
        ("Маршрут: Supreme Court Lat + Mount Vernon Lat", "388906", "387081"),

        # Числа из текста статьи
        ("Числа текста: Даты 1930+2000+1920", "193020", "001920"),
        ("Числа текста: M.7.7 Gall 18th cent 300 yr", "070718", "030000"),
        ("Числа текста: 40 taels 10 gold 221 206", "404010", "221206"),
    ]

    sequences = []
    seen = set()

    for desc, lat, lon in raw_coords + cross_pairs:
        s = lat + lon
        digits = [int(c) for c in s if c.isdigit()]
        if len(digits) != 12:
            continue
        key = tuple(digits)
        if key not in seen:
            seen.add(key)
            sequences.append((desc, digits))

    return sequences

def tokenize_whitespace(text: str) -> list[str]:
    tokens = []
    for t in text.split():
        c = re.sub(r"^[^\w]+|[^\w]+$", "", t).strip().lower()
        if c:
            tokens.append(c)
    return tokens

def tokenize_regex(text: str) -> list[str]:
    return [w.lower() for w in re.findall(r"[a-zA-Z]+", text)]

def main():
    print("=" * 80, flush=True)
    print("СПЕЦИАЛИЗИРОВАННОЕ ТЕСТИРОВАНИЕ ГИПОТЕЗЫ СОКРЫТИЯ СИД-ФРАЗЫ (v2.2)", flush=True)
    print("В ДРУГИХ РАЗДЕЛАХ СТАТЬИ («SECURING WEALTH IN POETRY»)", flush=True)
    print(f"Целевой адрес: {TARGET_ADDRESS}", flush=True)
    print(f"Целевой Hash160: {TARGET_H160.hex()}", flush=True)
    print("=" * 80, flush=True)

    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        wordlist = [line.strip().lower() for line in f if line.strip()]
    word_to_idx = {w: i for i, w in enumerate(wordlist)}
    bip_set = set(wordlist)

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        raw_article = f.read()

    headers = ["Revolution", "Fiat", "Bitcoin", "Touchpoints", "Steganography", "Trithemian Seeds"]
    sections = {}
    for i, h in enumerate(headers):
        m = re.search(r"^(?:" + h + r")\s*$", raw_article, re.MULTILINE)
        if not m:
            print(f"ОШИБКА: Заголовок {h} не найден!", flush=True)
            return
        start_idx = m.end()
        if i < len(headers) - 1:
            next_h = headers[i + 1]
            m_next = re.search(r"^(?:" + next_h + r")\s*$", raw_article, re.MULTILINE)
            sections[h] = raw_article[start_idx:m_next.start()].strip()
        else:
            sections[h] = raw_article[start_idx:].strip()

    rev_paras = [p.strip() for p in sections["Revolution"].split("\n\n") if p.strip()]
    fiat_paras = [p.strip() for p in sections["Fiat"].split("\n\n") if p.strip()]
    btc_paras = [p.strip() for p in sections["Bitcoin"].split("\n\n") if p.strip()]
    tp_paras = [p.strip() for p in sections["Touchpoints"].split("\n\n") if p.strip()]
    steg_paras = [p.strip() for p in sections["Steganography"].split("\n\n") if p.strip()]
    ts_paras = [p.strip() for p in sections["Trithemian Seeds"].split("\n\n") if p.strip()]

    fiat_clean_p1 = fiat_paras[0].split("\n")[0].strip()
    fiat_narrative = "\n\n".join([fiat_clean_p1, fiat_paras[1], fiat_paras[2]])

    steg_clean_p3 = steg_paras[2].split("\n")[0].strip()
    steg_narrative_p1_p3 = "\n\n".join([steg_paras[0], steg_paras[1], steg_clean_p3])

    ts_clean_p1 = ts_paras[0].split("\n")[0].strip()
    ts_narrative_p1_p4 = "\n\n".join([ts_clean_p1, ts_paras[1], ts_paras[2], ts_paras[3]])

    tp_clean_paras = [p for p in tp_paras if not ("E9873D" in p or "witch collapse" in p)]
    tp_clean_text = "\n\n".join(tp_clean_paras)

    # 1. Формирование BIP-цепочек разделов (для Phase 1)
    bip_targets_raw = [
        ("Steganography Полный (WS)", tokenize_whitespace(sections["Steganography"])),
        ("Steganography Полный (RE)", tokenize_regex(sections["Steganography"])),
        ("Steganography История P1-P3", tokenize_whitespace("\n\n".join(steg_paras[:3]))),
        ("Fiat Полный (WS)", tokenize_whitespace(sections["Fiat"])),
        ("Fiat Полный (RE)", tokenize_regex(sections["Fiat"])),
        ("Fiat Нарратив Clean", tokenize_whitespace(fiat_narrative)),
        ("Bitcoin Полный (WS)", tokenize_whitespace(sections["Bitcoin"])),
        ("Bitcoin Полный (RE)", tokenize_regex(sections["Bitcoin"])),
        ("Touchpoints Полный (WS)", tokenize_whitespace(sections["Touchpoints"])),
        ("Touchpoints Чистый текст", tokenize_whitespace(tp_clean_text)),
        ("Trithemian Seeds Полный (WS)", tokenize_whitespace(sections["Trithemian Seeds"])),
        ("Trithemian Seeds Введение Clean", tokenize_whitespace(ts_narrative_p1_p4)),
        ("Trithemian Seeds Финал P10-P13", tokenize_whitespace("\n\n".join(ts_paras[9:]))),
        ("Revolution Полный (WS)", tokenize_whitespace(sections["Revolution"])),
        ("Комбинация: Fiat + Bitcoin", tokenize_whitespace(sections["Fiat"] + "\n\n" + sections["Bitcoin"])),
        ("Комбинация: Steganography + Trithemian Seeds", tokenize_whitespace(sections["Steganography"] + "\n\n" + sections["Trithemian Seeds"])),
    ]

    valid_bip_targets = [
        (name, [w for w in tokens if w in bip_set])
        for name, tokens in bip_targets_raw
        if len([w for w in tokens if w in bip_set]) >= 12
    ]

    # 2. Формирование текстов потока слов (для Phase 2)
    flow_targets = [
        # Steganography
        ("Steganography Полный", tokenize_whitespace(sections["Steganography"])),
        ("Steganography Washington Ink P3", tokenize_whitespace(steg_paras[2])),
        ("Steganography Washington Clean P3", tokenize_whitespace(steg_clean_p3)),
        ("Steganography P1-P3", tokenize_whitespace("\n\n".join(steg_paras[:3]))),
        ("Steganography Clean P1-P3", tokenize_whitespace(steg_narrative_p1_p3)),
        ("Steganography P3-P4 (115 слов)", tokenize_whitespace(steg_paras[2] + " " + steg_paras[3])),
        ("Steganography P2-P3 (127 слов)", tokenize_whitespace(steg_paras[1] + " " + steg_paras[2])),
        ("Steganography P4-P6", tokenize_whitespace("\n\n".join(steg_paras[3:]))),

        # Fiat
        ("Fiat Полный", tokenize_whitespace(sections["Fiat"])),
        ("Fiat Нарратив Clean (P1-P3)", tokenize_whitespace(fiat_narrative)),
        ("Fiat P2+P3 (150 слов)", tokenize_whitespace(fiat_paras[1] + "\n\n" + fiat_paras[2])),
        ("Fiat Гиперинфляция P2", tokenize_whitespace(fiat_paras[1])),
        ("Fiat Золото и беженцы P3", tokenize_whitespace(fiat_paras[2])),

        # Bitcoin
        ("Bitcoin Полный", tokenize_whitespace(sections["Bitcoin"])),
        ("Bitcoin Абзацы 1-4", tokenize_whitespace("\n\n".join(btc_paras))),
        ("Bitcoin P1-P3 (107 слов)", tokenize_whitespace(" ".join(btc_paras[:3]))),

        # Touchpoints
        ("Touchpoints Полный", tokenize_whitespace(sections["Touchpoints"])),
        ("Touchpoints Чистый текст", tokenize_whitespace(tp_clean_text)),
        ("Touchpoints P6-P7 (114 слов)", tokenize_whitespace(tp_clean_paras[3] + " " + tp_clean_paras[4])),
        ("Touchpoints Нарратив P6-P8", tokenize_whitespace("\n\n".join(tp_clean_paras[3:6]))),

        # Trithemian Seeds
        ("Trithemian Seeds Полный", tokenize_whitespace(sections["Trithemian Seeds"])),
        ("Trithemian Seeds P1-P2 (104 слова)", tokenize_whitespace(ts_paras[0] + " " + ts_paras[1])),
        ("Trithemian Seeds P1-P3 (129 слов)", tokenize_whitespace(ts_paras[0] + " " + ts_paras[1] + " " + ts_paras[2])),
        ("Trithemian Seeds P3-P4 (120 слов)", tokenize_whitespace(ts_paras[2] + " " + ts_paras[3])),
        ("Trithemian Seeds Миграция P4 (95 слов)", tokenize_whitespace(ts_paras[3])),
        ("Trithemian Seeds Введение Clean P1-P4", tokenize_whitespace(ts_narrative_p1_p4)),
        ("Trithemian Seeds Финал P10-P11 (119 слов)", tokenize_whitespace(ts_paras[9] + " " + ts_paras[10])),
        ("Trithemian Seeds Финал P10-P13", tokenize_whitespace("\n\n".join(ts_paras[9:]))),

        # Revolution
        ("Revolution Полный", tokenize_whitespace(sections["Revolution"])),
        ("Revolution P1-P2 (124 слова)", tokenize_whitespace(rev_paras[0] + " " + rev_paras[1])),
        ("Revolution P3-P4 (131 слово)", tokenize_whitespace(rev_paras[2] + " " + rev_paras[3])),
        ("Revolution P7 (128 слов)", tokenize_whitespace(rev_paras[6])),
        ("Revolution P8-P9 (110 слов)", tokenize_whitespace(rev_paras[7] + " " + rev_paras[8])),

        # Комбинации
        ("Комбинация: Fiat + Bitcoin", tokenize_whitespace(sections["Fiat"] + "\n\n" + sections["Bitcoin"])),
        ("Комбинация: Steganography + Trithemian Seeds", tokenize_whitespace(sections["Steganography"] + "\n\n" + sections["Trithemian Seeds"])),
    ]

    print("\nЦелевые блоки BIP-цепочек (Phase 1):", flush=True)
    for name, bips in valid_bip_targets:
        print(f"  - {name:48s}: {len(bips):3d} слов BIP-39", flush=True)

    print("\nЦелевые блоки общего потока слов (Phase 2):", flush=True)
    for name, tokens in flow_targets:
        print(f"  - {name:48s}: {len(tokens):4d} слов", flush=True)

    digit_sequences = generate_stories_digit_sequences()
    print(f"\nВсего сформировано 12-значных последовательностей координат: {len(digit_sequences)}", flush=True)

    # Параметры формулы:
    AUTHOR_STEPS = [10, 9, 11, 8, 12]
    offsets = [-3, -2, -1, 0, 1, 2, 3]
    start_mults = [0, 1]

    def get_linear_steps(N: int) -> list[int]:
        s_set = set(AUTHOR_STEPS)
        base = max(1, round(N / 12))
        for delta in (-3, -2, -1, 0, 1, 2, 3):
            s = base + delta
            if s >= 1:
                s_set.add(s)
        return sorted(s_set)

    # Расчет общего числа комбинаций:
    # Phase 1:
    combos_phase1 = 0
    for name, bips in valid_bip_targets:
        N = len(bips)
        lin_steps = get_linear_steps(N)
        # Linear: 1-based and 0-based
        combos_phase1 += len(lin_steps) * len(start_mults) * len(offsets) * len(digit_sequences) * 2
        # Modulo: 1-based and 0-based with author steps
        combos_phase1 += len(AUTHOR_STEPS) * len(start_mults) * len(offsets) * len(digit_sequences) * 2

    # Phase 2:
    combos_phase2 = 0
    for name, tokens in flow_targets:
        N = len(tokens)
        lin_steps = get_linear_steps(N)
        combos_phase2 += len(lin_steps) * len(start_mults) * len(offsets) * len(digit_sequences) * 2
        combos_phase2 += len(AUTHOR_STEPS) * len(start_mults) * len(offsets) * len(digit_sequences) * 2

    total_combos = combos_phase1 + combos_phase2
    print(f"\nИТОГО запланировано проверок комбинаций: {total_combos:,}", flush=True)
    print(f"  Этап 1 (BIP-39 цепочки со масштабированными шагами): {combos_phase1:,}", flush=True)
    print(f"  Этап 2 (Общие потоки слов со масштабированными шагами): {combos_phase2:,}", flush=True)

    tracker = ProgressTracker(total_combos, PROGRESS_FILE, update_interval=1.5)
    evaluator = CandidateEvaluator(word_to_idx, tracker, CANDIDATES_FILE, PASSPHRASES)

    with open(CANDIDATES_FILE, "a", encoding="utf-8") as valid_header:
        valid_header.write(f"\n--- ЗАПУСК ТЕСТИРОВАНИЯ ДРУГИХ РАЗДЕЛОВ v2.2 {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

    try:
        # =================================================================
        # ЭТАП 1: ИНДЕКСАЦИЯ ПО ЦЕПОЧКАМ BIP-39 СЛОВ РАЗДЕЛОВ
        # =================================================================
        for name, bip_words in valid_bip_targets:
            if evaluator.found:
                break
            N = len(bip_words)
            lin_steps = get_linear_steps(N)
            tracker.set_phase(f"Этап 1: BIP {name[:22]} (N={N})")

            # 1. Линейный режим
            for seq_desc, digits in digit_sequences:
                if evaluator.found:
                    break
                for step in lin_steps:
                    for m in start_mults:
                        for off in offsets:
                            # 1-based Linear
                            tracker.advance(1)
                            idx_1lin = [digits[i] + step * (i + m) + off - 1 for i in range(12)]
                            if all(0 <= idx < N for idx in idx_1lin):
                                cand = [bip_words[idx] for idx in idx_1lin]
                                desc = f"{name} | 1-based Linear | {seq_desc} | s={step}, m={m}, off={off}"
                                if evaluator.evaluate(cand, desc, is_linear=True):
                                    return

                            # 0-based Linear
                            tracker.advance(1)
                            idx_0lin = [digits[i] + step * (i + m) + off for i in range(12)]
                            if all(0 <= idx < N for idx in idx_0lin):
                                cand = [bip_words[idx] for idx in idx_0lin]
                                desc = f"{name} | 0-based Linear | {seq_desc} | s={step}, m={m}, off={off}"
                                if evaluator.evaluate(cand, desc, is_linear=True):
                                    return

            # 2. Модульный режим (авторские шаги 10, 9, 11, 8, 12)
            for seq_desc, digits in digit_sequences:
                if evaluator.found:
                    break
                for step in AUTHOR_STEPS:
                    for m in start_mults:
                        for off in offsets:
                            # 1-based Modulo
                            tracker.advance(1)
                            idx_1mod = [(digits[i] + step * (i + m) + off - 1) % N for i in range(12)]
                            cand = [bip_words[idx] for idx in idx_1mod]
                            desc = f"{name} | 1-based Modulo | {seq_desc} | s={step}, m={m}, off={off}"
                            if evaluator.evaluate(cand, desc, is_linear=False):
                                return

                            # 0-based Modulo
                            tracker.advance(1)
                            idx_0mod = [(digits[i] + step * (i + m) + off) % N for i in range(12)]
                            cand = [bip_words[idx] for idx in idx_0mod]
                            desc = f"{name} | 0-based Modulo | {seq_desc} | s={step}, m={m}, off={off}"
                            if evaluator.evaluate(cand, desc, is_linear=False):
                                return

        # =================================================================
        # ЭТАП 2: ИНДЕКСАЦИЯ ПО ОБЩИМ ПОТОКАМ СЛОВ РАЗДЕЛОВ
        # =================================================================
        for name, words_flow in flow_targets:
            if evaluator.found:
                break
            N = len(words_flow)
            lin_steps = get_linear_steps(N)
            tracker.set_phase(f"Этап 2: Поток {name[:22]} (N={N})")

            # 1. Линейный режим
            for seq_desc, digits in digit_sequences:
                if evaluator.found:
                    break
                for step in lin_steps:
                    for m in start_mults:
                        for off in offsets:
                            # 1-based Linear
                            tracker.advance(1)
                            idx_1lin = [digits[i] + step * (i + m) + off - 1 for i in range(12)]
                            if all(0 <= idx < N for idx in idx_1lin):
                                cand = [words_flow[idx] for idx in idx_1lin]
                                if all(w in bip_set for w in cand):
                                    desc = f"{name} | Поток 1-based Linear | {seq_desc} | s={step}, m={m}, off={off}"
                                    if evaluator.evaluate(cand, desc, is_linear=True):
                                        return

                            # 0-based Linear
                            tracker.advance(1)
                            idx_0lin = [digits[i] + step * (i + m) + off for i in range(12)]
                            if all(0 <= idx < N for idx in idx_0lin):
                                cand = [words_flow[idx] for idx in idx_0lin]
                                if all(w in bip_set for w in cand):
                                    desc = f"{name} | Поток 0-based Linear | {seq_desc} | s={step}, m={m}, off={off}"
                                    if evaluator.evaluate(cand, desc, is_linear=True):
                                        return

            # 2. Модульный режим
            for seq_desc, digits in digit_sequences:
                if evaluator.found:
                    break
                for step in AUTHOR_STEPS:
                    for m in start_mults:
                        for off in offsets:
                            # 1-based Modulo
                            tracker.advance(1)
                            idx_1mod = [(digits[i] + step * (i + m) + off - 1) % N for i in range(12)]
                            cand = [words_flow[idx] for idx in idx_1mod]
                            if all(w in bip_set for w in cand):
                                desc = f"{name} | Поток 1-based Modulo | {seq_desc} | s={step}, m={m}, off={off}"
                                if evaluator.evaluate(cand, desc, is_linear=False):
                                    return

                            # 0-based Modulo
                            tracker.advance(1)
                            idx_0mod = [(digits[i] + step * (i + m) + off) % N for i in range(12)]
                            cand = [words_flow[idx] for idx in idx_0mod]
                            if all(w in bip_set for w in cand):
                                desc = f"{name} | Поток 0-based Modulo | {seq_desc} | s={step}, m={m}, off={off}"
                                if evaluator.evaluate(cand, desc, is_linear=False):
                                    return

    finally:
        evaluator.close()

    tracker.finish(evaluator.found_details)

if __name__ == "__main__":
    main()
