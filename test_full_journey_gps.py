"""
Скрипт глубокого и оптимизированного тестирования гипотезы маршрута миграции
(Циндао -> Тайвань) по тексту главы «Revolution» статьи «Securing Wealth in Poetry».

Ключевые оптимизации и исправления:
1. Исключение повторов:
   - Кэширование проверенных мнемоник (seen_mnemonics): устранено дублирование
     вычислений PBKDF2 (более 12 000 повторов в предыдущей версии).
   - Удалены идентичные цепочки слов (story_all_paras и story_revolution.txt).
2. Полное соответствие формуле автора:
   - Каноническое 1-based индексирование Trithemius: (d_i + step * i - 1 + off).
   - 0-based индексирование: (d_i + step * i + off).
   - Шаги 10 (авторский), 9 (идеально для 112 слов: 9*11+9=108 <= 112), 11, 8, 12.
   - Линейное индексирование и циклическое (modulo).
3. Высокая производительность:
   - coincurve (libsecp256k1) для мгновенной проверки публичных ключей.
   - Предварительная проверка 4-битной контрольной суммы SHA-256 (BIP-39).
   - Многопоточная проверка паролей через ThreadPoolExecutor (8 потоков).
   - Пакетная буферизация дисковой записи valid_journey_candidates.txt.
4. Требования пользователя к отслеживанию прогресса:
   - Консольный вывод с flush=True (процент, проверено, скорость, прошедшее время, ETA).
   - Периодическая запись в c:\\Users\\Vladislav\\Desktop\\Новая папка\\progress.txt каждые 2.0-2.5 сек.
   - Итоговый подробный отчет в progress.txt с сохранением полной статистики.
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

# =====================================================================
# Конфигурация и пути
# =====================================================================
BASE_DIR = Path(r"c:\Users\Vladislav\Desktop\Новая папка")
TEXT_FILE = BASE_DIR / "clean_article.txt"
WORDS_FILE = BASE_DIR / "word.txt"
PROGRESS_FILE = BASE_DIR / "progress.txt"
CANDIDATES_FILE = BASE_DIR / "valid_journey_candidates.txt"
FOUND_FILE = BASE_DIR / "FOUND_SOLUTION.txt"

TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
TARGET_H160 = base58.b58decode_check(TARGET_ADDRESS)[1:]

SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

# Кодовые фразы для тестирования кандидатов
PASSPHRASES = [
    "",
    "Trithemius",
    "trithemius",
    "mnemonic",
    "Revolution",
    "revolution",
    "Poetry",
    "time",
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
    """
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k, master_c = I[:32], I[32:]

    # 1. Master key 'm'
    for comp in (True, False):
        pub = coincurve.PrivateKey(master_k).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m", comp

    # 2. m/44'/0'/0'/0/0, 0/1, 0/2
    k44, c44 = ckd_priv(master_k, master_c, 44 + 0x80000000)
    if k44 is None:
        return None
    k44_0, c44_0 = ckd_priv(k44, c44, 0 + 0x80000000)
    if k44_0 is None:
        return None
    k44_0_0, c44_0_0 = ckd_priv(k44_0, c44_0, 0 + 0x80000000)
    if k44_0_0 is None:
        return None

    # m/44'/0'/0'
    for comp in (True, False):
        pub = coincurve.PrivateKey(k44_0_0).public_key.format(compressed=comp)
        if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
            return "m/44'/0'/0'", comp

    k44_0_0_0, c44_0_0_0 = ckd_priv(k44_0_0, c44_0_0, 0)
    if k44_0_0_0 is not None:
        # m/44'/0'/0'/0
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

    # 3. m/0'/0'/0'
    k0, c0 = ckd_priv(master_k, master_c, 0 + 0x80000000)
    if k0 is not None:
        k0_0, c0_0 = ckd_priv(k0, c0, 0 + 0x80000000)
        if k0_0 is not None:
            k0_0_0, _ = ckd_priv(k0_0, c0_0, 0 + 0x80000000)
            if k0_0_0 is not None:
                for comp in (True, False):
                    pub = coincurve.PrivateKey(k0_0_0).public_key.format(compressed=comp)
                    if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                        return "m/0'/0'/0'", comp

    # 4. m/0/0 и m/0
    km0, cm0 = ckd_priv(master_k, master_c, 0)
    if km0 is not None:
        for comp in (True, False):
            pub = coincurve.PrivateKey(km0).public_key.format(compressed=comp)
            if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                return "m/0", comp

        km0_0, _ = ckd_priv(km0, cm0, 0)
        if km0_0 is not None:
            for comp in (True, False):
                pub = coincurve.PrivateKey(km0_0).public_key.format(compressed=comp)
                if hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest() == TARGET_H160:
                    return "m/0/0", comp

    return None

def verify_checksum(idxs_12: list[int]) -> bool:
    """Ультрабыстрая проверка 4-битной контрольной суммы BIP-39."""
    val = 0
    for idx in idxs_12:
        val = (val << 11) | idx
    entropy = (val >> 4).to_bytes(16, "big")
    expected_cs = hashlib.sha256(entropy).digest()[0] >> 4
    return (val & 0x0F) == expected_cs

# =====================================================================
# Класс отслеживания прогресса (Консоль + Файл progress.txt)
# =====================================================================
class ProgressTracker:
    def __init__(self, total_combos: int, progress_file: Path, update_interval: float = 2.0):
        self.total = total_combos
        self.progress_file = progress_file
        self.update_interval = update_interval
        self.start_time = time.time()
        self.last_update = 0.0
        self.checked = 0
        self.valid_checksums = 0
        self.unique_mnemonics = 0
        self.current_phase = "Инициализация"
        self.last_valid_mnemonic = ""
        self.found = False

    def set_phase(self, phase_name: str):
        self.current_phase = phase_name
        self.update(force=True)

    def advance(self, count: int = 1):
        self.checked += count
        if self.checked % 500 == 0:
            now = time.time()
            if now - self.last_update >= self.update_interval:
                self.update_at(now)

    def add_valid(self, mnemonic: str):
        self.valid_checksums += 1
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
            f"Фаза: {self.current_phase} | Валидных: {self.valid_checksums} (Уник: {self.unique_mnemonics})"
        )
        print(status_text, flush=True)

        try:
            with open(self.progress_file, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(" СТАТУС ТЕСТИРОВАНИЯ МАРШРУТА МИГРАЦИИ (GPS REVOLUTION)\n")
                f.write("=" * 70 + "\n")
                f.write(f"Состояние:        {'НАЙДЕНО РЕШЕНИЕ!' if self.found else 'ВЫПОЛНЯЕТСЯ'}\n")
                f.write(f"Текущая фаза:     {self.current_phase}\n")
                f.write(f"Прогресс:         {pct:.2f}%\n")
                f.write(f"Проверено:        {self.checked:,} из {self.total:,}\n")
                f.write(f"Скорость:         {speed:,.1f} комбинаций/сек\n")
                f.write(f"Время работы:     {elapsed:.1f} сек\n")
                f.write(f"Расчётное ETA:    {eta_str}\n")
                f.write(f"Валидных чексумм: {self.valid_checksums}\n")
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
        print(f"Найдено валидных BIP-39 чексумм: {self.valid_checksums} (уникальных мнемоник: {self.unique_mnemonics})", flush=True)
        if found_details:
            print("🎉🎉🎉 НАЙДЕНО СОВПАДЕНИЕ С ЦЕЛЕВЫМ КОШЕЛЬКОМ! 🎉🎉🎉", flush=True)
            print(found_details, flush=True)
        print("=" * 70 + "\n", flush=True)

        try:
            with open(self.progress_file, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(" ТЕСТИРОВАНИЕ ЗАВЕРШЕНО\n")
                f.write("=" * 70 + "\n")
                f.write(f"Статус:           {'УСПЕХ! ЦЕЛЕВОЙ АДРЕС НАЙДЕН' if self.found else 'ЗАВЕРШЕНО (Совпадений с адресом нет)'}\n")
                f.write(f"Всего проверено:  {self.checked:,} комбинаций\n")
                f.write(f"Затрачено времени:{elapsed:.2f} сек\n")
                f.write(f"Средняя скорость: {speed:,.1f} комб/с\n")
                f.write(f"Валидных чексумм: {self.valid_checksums}\n")
                f.write(f"Уникальных сидов: {self.unique_mnemonics}\n")
                if found_details:
                    f.write("\nДЕТАЛИ НАЙДЕННОГО КОШЕЛЬКА:\n" + found_details + "\n")
                f.write("=" * 70 + "\n")
                f.flush()
        except Exception:
            pass

# =====================================================================
# Оценщик мнемоник с дедупликацией и пулом потоков
# =====================================================================
class CandidateEvaluator:
    def __init__(self, word_to_idx: dict[str, int], tracker: ProgressTracker, candidates_file: Path, passphrases: list[str]):
        self.word_to_idx = word_to_idx
        self.tracker = tracker
        self.candidates_file = candidates_file
        self.passphrases = passphrases
        self.seen_mnemonics = set()
        self.out_f = open(candidates_file, "a", encoding="utf-8")
        self.out_buffer = []
        self.pool = ThreadPoolExecutor(max_workers=min(8, len(passphrases)))

    def _eval_one(self, mnemonic: str, pw: str):
        salt = ("mnemonic" + pw).encode("utf-8")
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048)
        match = check_seed_fast(seed)
        if match:
            return pw, match
        return None

    def evaluate(self, words_12: list[str], desc: str) -> bool:
        idxs = [self.word_to_idx.get(w.lower()) for w in words_12]
        if any(i is None for i in idxs):
            return False

        if not verify_checksum(idxs):
            return False

        mnemonic = " ".join(words_12)
        self.tracker.add_valid(mnemonic)

        # Дедупликация: не пересчитывать сиды для уже проверенной мнемоники
        if mnemonic in self.seen_mnemonics:
            return False
        self.seen_mnemonics.add(mnemonic)
        self.tracker.add_unique()

        self.out_buffer.append(f"{mnemonic} | {desc}\n")
        if len(self.out_buffer) >= 25:
            self.out_f.writelines(self.out_buffer)
            self.out_f.flush()
            self.out_buffer.clear()

        # Параллельная проверка паролей через пул потоков
        futures = [self.pool.submit(self._eval_one, mnemonic, pw) for pw in self.passphrases]
        for f in futures:
            res = f.result()
            if res:
                pw, match = res
                path, comp = match
                details = (
                    f"Фраза:    {mnemonic}\n"
                    f"Пароль:   '{pw}'\n"
                    f"Путь:     {path} (compressed={comp})\n"
                    f"Адрес:    {TARGET_ADDRESS}\n"
                    f"Алгоритм: {desc}\n"
                )
                with open(FOUND_FILE, "w", encoding="utf-8") as f_out:
                    f_out.write(details)
                self.tracker.finish(details)
                return True
        return False

    def close(self):
        if self.out_buffer:
            self.out_f.writelines(self.out_buffer)
            self.out_f.flush()
            self.out_buffer.clear()
        self.out_f.close()
        self.pool.shutdown(wait=False)

# =====================================================================
# База координат маршрута миграции
# =====================================================================
# 1. Циндао — 6-значные компоненты широты и долготы
QINGDAO_6DIGIT = [
    ("Циндао Мэрия Lat (36.0669)", "360669"),
    ("Циндао Мэрия Lat v2 (36.0671)", "360671"),
    ("Циндао Мэрия Lon (120.383)", "120383"),
    ("Циндао Мэрия Lon v2 (120.382)", "120382"),
    ("Циндао Мэрия Lon drop100 (20.3827)", "203827"),
    ("Циндао Мэрия Lon drop100 v2", "203830"),
    ("Циндао Порт Даган Lat (36.0936)", "360936"),
    ("Циндао Порт Даган Lon (120.317)", "120317"),
    ("Циндао Порт Даган Lon v2 (120.316)", "120316"),
    ("Циндао Порт Даган Lon drop100 (20.3167)", "203167"),
    ("Циндао Порт Даган Станция (36.0844)", "360844"),
    ("Циндао Порт Даган Станция Lon", "120321"),
    ("Циндао Порт общий Lat (36.0566)", "360566"),
    ("Циндао Порт общий Lon (120.320)", "120320"),
    ("Циндао Пасс. причал Даган Lat (36.0872)", "360872"),
    ("Циндао Пирс Чжаньцяо Lat (36.0600)", "360600"),
    ("Циндао Пирс Чжаньцяо Lat v2 (36.0617)", "360617"),
    ("Циндао Пирс Чжаньцяо Lat v3 (36.0583)", "360583"),
    ("Циндао Пирс Чжаньцяо Lon (120.315)", "120315"),
    ("Циндао Пирс Чжаньцяо Lon v2 (120.314)", "120314"),
    ("Циндао Пирс Чжаньцяо Lon v3 (120.313)", "120313"),
    ("Циндао Пирс Чжаньцяо Lon drop100", "203148"),
    ("Циндао Павильон Хуэйланьгэ (36.0583)", "360583"),
    ("Циндао Павильон Хуэйланьгэ Lon", "120316"),
    ("Циндао Вокзал 1901 Lat (36.0642)", "360642"),
    ("Циндао Вокзал 1901 Lat v2 (36.0634)", "360634"),
    ("Циндао Вокзал 1901 Lon (120.308)", "120308"),
    ("Циндао Вокзал 1901 Lon v2 (120.311)", "120311"),
    ("Циндао Вокзал 1901 Lon drop100", "203083"),
    ("Циндао Бадагуань Lat (36.0578)", "360578"),
    ("Циндао Бадагуань Lon (120.352)", "120352"),
]

# 2. Тайвань (Цзилун и Тайбэй) — 6-значные компоненты
TAIWAN_6DIGIT = [
    ("Порт Цзилун Lat (25.1311)", "251311"),
    ("Порт Цзилун Lat v2 (25.1405)", "251405"),
    ("Порт Цзилун Lat v3 (25.1300)", "251300"),
    ("Порт Цзилун Lon (121.743)", "121743"),
    ("Порт Цзилун Lon v2 (121.744)", "121744"),
    ("Порт Цзилун Lon v3 (121.750)", "121750"),
    ("Порт Цзилун Lon v4 (121.740)", "121740"),
    ("Порт Цзилун Lon drop100 (21.7431)", "217431"),
    ("Цзилун Морвокзал Lat (25.1325)", "251325"),
    ("Цзилун Морвокзал Lon (121.741)", "121741"),
    ("Город Цзилун Lat (25.1333)", "251333"),
    ("Город Цзилун Lon (121.733)", "121733"),
    ("Тайбэй Мэрия Lat (25.0375)", "250375"),
    ("Тайбэй Мэрия Lon (121.564)", "121564"),
    ("Тайбэй Мэрия Lon v2 (121.527)", "121527"),
    ("Тайбэй Вокзал Lat (25.0478)", "250478"),
    ("Тайбэй Вокзал Lat v2 (25.0330)", "250330"),
    ("Тайбэй Вокзал Lat v3 (25.0531)", "250531"),
    ("Тайбэй Вокзал Lon (121.517)", "121517"),
    ("Тайбэй Вокзал Lon v2 (121.565)", "121565"),
    ("Тайбэй Вокзал Lon v3 (121.532)", "121532"),
    ("Тайбэй Вокзал Lon v4 (121.526)", "121526"),
]

# 3. Одиночные локации (полные 12-значные пары Lat+Lon и Lon+Lat)
SINGLE_LOCATIONS = [
    ("Циндао Мэрия", "360669", "120383"),
    ("Циндао Мэрия drop100", "360669", "203827"),
    ("Циндао Порт Даган", "360936", "120317"),
    ("Циндао Порт Даган drop100", "360936", "203167"),
    ("Циндао Пассажирский вокзал", "360872", "120315"),
    ("Циндао Пирс Чжаньцяо", "360600", "120315"),
    ("Циндао Пирс Чжаньцяо drop100", "360600", "203148"),
    ("Циндао Павильон Хуэйланьгэ", "360583", "120316"),
    ("Циндао Вокзал 1901", "360642", "120308"),
    ("Циндао Вокзал drop100", "360642", "203083"),
    ("Циндао Бадагуань", "360578", "120352"),
    ("Порт Цзилун", "251311", "121743"),
    ("Порт Цзилун drop100", "251311", "217431"),
    ("Цзилун Морвокзал", "251325", "121741"),
    ("Город Цзилун", "251333", "121733"),
    ("Тайбэй Мэрия", "250375", "121564"),
    ("Тайбэй Вокзал", "250478", "121517"),
    ("Ванкувер Канада", "492827", "123120"),
    ("Ванкувер Канада drop100", "492827", "231207"),
    ("Цинь Сяньян Дворец", "344158", "108863"),
    ("Цинь Мавзолей Шихуана", "343817", "109254"),
    ("Триттенхайм", "498258", "069006"),
    ("Оксфорд Jesus College", "517534", "012569"),
    ("Маунт-Вернон", "387081", "770861"),
    ("Верховный суд США", "388906", "770044"),
]

def generate_journey_digit_sequences():
    """
    Генерирует полный набор 12-значных последовательностей цифр:
    - Комбинированные маршруты: 6 цифр Циндао + 6 цифр Тайваня
    - Комбинированные маршруты: 6 цифр Тайваня + 6 цифр Циндао
    - Одиночные локации (Lat+Lon и Lon+Lat)
    - Компактные координаты 3+3
    - Последовательность чисел рассказа (1930, 2000, 1920...)
    """
    sequences = []
    seen = set()

    def add_seq(desc, s):
        digits = [int(c) for c in s if c.isdigit()]
        if len(digits) != 12:
            return
        key = tuple(digits)
        if key not in seen:
            seen.add(key)
            sequences.append((desc, digits))

    # 1. Комбинации маршрута Циндао -> Тайвань (6 + 6)
    for q_desc, q_str in QINGDAO_6DIGIT:
        for t_desc, t_str in TAIWAN_6DIGIT:
            add_seq(f"Маршрут: {q_desc} + {t_desc}", q_str + t_str)
            add_seq(f"Маршрут обр: {t_desc} + {q_desc}", t_str + q_str)

    # 2. Одиночные локации
    for loc_desc, lat, lon in SINGLE_LOCATIONS:
        add_seq(f"{loc_desc} (Lat+Lon)", lat + lon)
        add_seq(f"{loc_desc} (Lon+Lat)", lon + lat)

    # 3. Компактные 3+3 (Циндао 3+3 + Тайвань 3+3)
    q_compacts = [("Циндао Мэрия 3+3", "360120"), ("Циндао Порт 3+3", "360120"), ("Циндао Вокзал 3+3", "360120")]
    t_compacts = [("Цзилун Порт 3+3", "251121"), ("Тайбэй Мэрия 3+3", "250121")]
    for q_d, q_c in q_compacts:
        for t_d, t_c in t_compacts:
            add_seq(f"Компактный маршрут: {q_d} + {t_d}", q_c + t_c)
            add_seq(f"Компактный маршрут обр: {t_d} + {q_d}", t_c + q_c)

    # 4. Числа рассказа (даты начала рассказа)
    add_seq("Даты начала рассказа: 1930+2000+1920", "193020001920")

    return sequences

# =====================================================================
# Токенизаторы
# =====================================================================
def tokenize_whitespace(text: str) -> list[str]:
    tokens = []
    for t in text.split():
        c = re.sub(r"^[^\w]+|[^\w]+$", "", t).strip()
        if c:
            tokens.append(c)
    return tokens

def tokenize_regex(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z]+", text)

# =====================================================================
# Основная процедура тестирования
# =====================================================================
def main():
    print("=" * 75, flush=True)
    print("ТЕСТИРОВАНИЕ ГИПОТЕЗЫ МАРШРУТА МИГРАЦИИ (ЦИНДАО -> ТАЙВАНЬ)", flush=True)
    print("ГЛАВА «REVOLUTION» — ПОЛНЫЙ ОХВАТ И АБЗАЦЫ", flush=True)
    print(f"Целевой адрес: {TARGET_ADDRESS}", flush=True)
    print("=" * 75, flush=True)

    # 1. Загрузка словаря BIP-39
    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        wordlist = [line.strip().lower() for line in f if line.strip()]
    word_to_idx = {w: i for i, w in enumerate(wordlist)}
    bip_set = set(wordlist)

    # 2. Загрузка текста рассказа
    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        clean_article_raw = f.read()

    sec1_text = clean_article_raw.split("Fiat")[0].split("Revolution")[1].strip()
    paras_sec1 = [p.strip() for p in sec1_text.split("\n\n") if p.strip()]

    # Текст без 9-го абзаца (только история дедушки, 8 абзацев)
    story_8_paras = "\n\n".join(paras_sec1[:8])
    # Полный текст главы (все 9 абзацев)
    story_all_paras = sec1_text

    # 3. Подготовка последовательностей координат
    digit_sequences = generate_journey_digit_sequences()
    print(f"Сгенерировано уникальных 12-значных последовательностей координат: {len(digit_sequences):,}", flush=True)

    # 4. Вариации параметров формулы:
    # Шаги: 10 (авторский), 9 (идеально для 112 слов: 9*11+9=108 <= 112), 11, 8, 12
    # Старт множителя: 0 (d_i + step*i), 1 (d_i + step*(i+1))
    # Смещения: -2, -1, 0, 1, 2
    formula_variations = []
    for step in [10, 9, 11, 8, 12]:
        for start_mult in [0, 1]:
            for offset in range(-2, 3):
                formula_variations.append((step, start_mult, offset))

    print(f"Вариаций параметров формулы d_i + step*(i+m) + off: {len(formula_variations)}", flush=True)

    # 5. Уникальные цепочки BIP-39 слов (без дубликатов):
    bip_chains = [
        ("Полный рассказ (112 BIP-слов, whitespace)", tokenize_whitespace(story_all_paras)),
        ("Рассказ 8 абзацев (103 BIP-слова, whitespace)", tokenize_whitespace(story_8_paras)),
        ("Полный рассказ (115 BIP-слов, regex)", tokenize_regex(story_all_paras)),
        ("Рассказ 8 абзацев (106 BIP-слов, regex)", tokenize_regex(story_8_paras)),
    ]

    # 6. Потоки общего текста (все слова):
    all_word_flows = [
        ("Абзац 7 (Циндао и юаньбао, 127 слов)", tokenize_whitespace(paras_sec1[6])),
        ("Абзац 8 (Тайвань и Канада, 74 слова)", tokenize_whitespace(paras_sec1[7])),
        ("Абзацы 7+8 (Маршрут Циндао->Тайвань, 201 слово)", tokenize_whitespace(paras_sec1[6] + "\n" + paras_sec1[7])),
        ("Полный рассказ (все 596 слов)", tokenize_whitespace(story_all_paras)),
    ]

    # 7. Расчет точного количества комбинаций:
    # Этап 1: BIP-цепочки:
    # 4 цепочки * len(seq) * len(forms) * 3 режима (1-based linear, 1-based mod, 0-based mod)
    combos_bip = len(bip_chains) * len(digit_sequences) * len(formula_variations) * 3

    # Этап 2: Общие потоки слов: len(flows) * len(seq) * len(forms) * 2 (1-based mod + 0-based mod)
    combos_flows = len(all_word_flows) * len(digit_sequences) * len(formula_variations) * 2

    # Этап 3: Масштабированные шаги по 596 словам рассказа (шаги 45..55):
    scaled_forms = [(s, off, m) for s in [45, 48, 50, 52, 55] for off in range(-2, 3) for m in [0, 1]]
    combos_scaled = len(digit_sequences) * len(scaled_forms) * 2

    total_combos = combos_bip + combos_flows + combos_scaled
    print(f"ВСЕГО запланировано проверок комбинаций: {total_combos:,}", flush=True)

    tracker = ProgressTracker(total_combos, PROGRESS_FILE, update_interval=2.0)
    evaluator = CandidateEvaluator(word_to_idx, tracker, CANDIDATES_FILE, PASSPHRASES)

    with open(CANDIDATES_FILE, "a", encoding="utf-8") as valid_header:
        valid_header.write(f"\n--- СИСТЕМНЫЙ ЗАПУСК ТЕСТИРОВАНИЯ {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

    try:
        # =================================================================
        # ЭТАП 1: ИНДЕКСАЦИЯ ПО ЦЕПОЧКЕ BIP-39 СЛОВ РАССКАЗА
        # (112 слов идеально соотносится с диапазоном d_i + 10*i до 119)
        # =================================================================
        tracker.set_phase("Этап 1: Цепочка BIP-39 слов рассказа")
        for chain_name, raw_tokens in bip_chains:
            bip_words = [w.lower() for w in raw_tokens if w.lower() in bip_set]
            n_bip = len(bip_words)
            print(f"\n---> Тестирование цепочки: {chain_name} (слов BIP: {n_bip})", flush=True)

            for seq_desc, digits in digit_sequences:
                for step, start_mult, offset in formula_variations:
                    # 1. Канонический 1-based (авторский Trithemius) строго линейный (в границах)
                    tracker.advance(1)
                    idx_1based = [digits[i] + step * (i + start_mult) + offset - 1 for i in range(12)]
                    if all(0 <= idx < n_bip for idx in idx_1based):
                        cand_1 = [bip_words[idx] for idx in idx_1based]
                        desc_1 = f"{chain_name} | 1-based Линейно | {seq_desc} | s={step}, m={start_mult}, off={offset}"
                        if evaluator.evaluate(cand_1, desc_1):
                            return

                    # 2. Канонический 1-based Modulo
                    tracker.advance(1)
                    idx_1mod = [(digits[i] + step * (i + start_mult) + offset - 1) % n_bip for i in range(12)]
                    cand_1mod = [bip_words[idx] for idx in idx_1mod]
                    desc_1mod = f"{chain_name} | 1-based Modulo | {seq_desc} | s={step}, m={start_mult}, off={offset}"
                    if evaluator.evaluate(cand_1mod, desc_1mod):
                        return

                    # 3. 0-based Modulo
                    tracker.advance(1)
                    idx_0mod = [(digits[i] + step * (i + start_mult) + offset) % n_bip for i in range(12)]
                    cand_0mod = [bip_words[idx] for idx in idx_0mod]
                    desc_0mod = f"{chain_name} | 0-based Modulo | {seq_desc} | s={step}, m={start_mult}, off={offset}"
                    if evaluator.evaluate(cand_0mod, desc_0mod):
                        return

        # =================================================================
        # ЭТАП 2: ИНДЕКСАЦИЯ ПО ОБЩЕМУ ПОТОКУ СЛОВ (ОТДЕЛЬНЫЕ АБЗАЦЫ И РАССКАЗ)
        # =================================================================
        tracker.set_phase("Этап 2: Общий поток слов рассказа и абзацев")
        for flow_name, words_flow in all_word_flows:
            n_flow = len(words_flow)
            print(f"\n---> Тестирование потока: {flow_name} (всего слов: {n_flow})", flush=True)

            for seq_desc, digits in digit_sequences:
                for step, start_mult, offset in formula_variations:
                    # 1. 1-based Modulo
                    tracker.advance(1)
                    idx_1 = [(digits[i] + step * (i + start_mult) + offset - 1) % n_flow for i in range(12)]
                    cand_1 = [words_flow[idx] for idx in idx_1]
                    if all(w.lower() in bip_set for w in cand_1):
                        desc_1 = f"{flow_name} | 1-based Modulo | {seq_desc} | s={step}, m={start_mult}, off={offset}"
                        if evaluator.evaluate(cand_1, desc_1):
                            return

                    # 2. 0-based Modulo
                    tracker.advance(1)
                    idx_0 = [(digits[i] + step * (i + start_mult) + offset) % n_flow for i in range(12)]
                    cand_0 = [words_flow[idx] for idx in idx_0]
                    if all(w.lower() in bip_set for w in cand_0):
                        desc_0 = f"{flow_name} | 0-based Modulo | {seq_desc} | s={step}, m={start_mult}, off={offset}"
                        if evaluator.evaluate(cand_0, desc_0):
                            return

        # =================================================================
        # ЭТАП 3: МАСШТАБИРОВАННЫЕ ШАГИ ПО ВСЕМУ ТЕКСТУ РАССКАЗА
        # (Шаги 45..55 для покрытия всех 596 слов рассказа)
        # =================================================================
        tracker.set_phase("Этап 3: Масштабированные шаги по всем 596 словам рассказа")
        words_full = tokenize_whitespace(story_all_paras)
        n_full = len(words_full)

        for seq_desc, digits in digit_sequences:
            for s_step, s_off, s_mult in scaled_forms:
                # 1. 1-based
                tracker.advance(1)
                idx_scale_1 = [(digits[i] + s_step * (i + s_mult) + s_off - 1) % n_full for i in range(12)]
                cand_scale_1 = [words_full[idx] for idx in idx_scale_1]
                if all(w.lower() in bip_set for w in cand_scale_1):
                    desc_scale_1 = f"Полный рассказ scaled 1-based | s={s_step}, m={s_mult}, off={s_off} | {seq_desc}"
                    if evaluator.evaluate(cand_scale_1, desc_scale_1):
                        return

                # 2. 0-based
                tracker.advance(1)
                idx_scale_0 = [(digits[i] + s_step * (i + s_mult) + s_off) % n_full for i in range(12)]
                cand_scale_0 = [words_full[idx] for idx in idx_scale_0]
                if all(w.lower() in bip_set for w in cand_scale_0):
                    desc_scale_0 = f"Полный рассказ scaled 0-based | s={s_step}, m={s_mult}, off={s_off} | {seq_desc}"
                    if evaluator.evaluate(cand_scale_0, desc_scale_0):
                        return

    finally:
        evaluator.close()

    tracker.finish()

if __name__ == "__main__":
    main()
