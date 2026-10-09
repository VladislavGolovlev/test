import hashlib
import hmac
import sys
from pathlib import Path
import ecdsa
import base58

# Настройка UTF-8 вывода для консоли Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Пути к файлам
WORDS_FILE = Path(r"c:\Users\Vladislav\Desktop\Новая папка\word.txt")
FOUND_WORDS_FILE = Path(r"c:\Users\Vladislav\Desktop\Новая папка\found_words.txt")
TARGET_ADDRESS = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"

# Пути деривации для адресов типа Legacy (1...)
DERIVATION_PATHS = [
    "m/44'/0'/0'/0/0",  # Стандарт BIP-44 (аккаунт 0, адрес 0)
    "m/44'/0'/0'/0/1",  # BIP-44 (адрес 1)
    "m/0'/0'/0'",      # Старый BIP-32
    "m/0/0",           # Electrum / Coinomi legacy
    "m/44'/0'/0'/0",   # Альтернативный путь
]

SECP256K1_ORDER = ecdsa.curves.SECP256k1.order

def get_pubkey(priv_bytes: bytes, compressed: bool = True) -> bytes:
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if not compressed:
        return b"\x04" + vk.to_string()
    pub = vk.to_string()
    prefix = b"\x02" if pub[-1] % 2 == 0 else b"\x03"
    return prefix + pub[:32]

def ckd_priv(parent_k: bytes, parent_c: bytes, index: int):
    is_hardened = index >= 0x80000000
    if is_hardened:
        data = b"\x00" + parent_k + index.to_bytes(4, "big")
    else:
        pub = get_pubkey(parent_k, compressed=True)
        data = pub + index.to_bytes(4, "big")
    I = hmac.new(parent_c, data, hashlib.sha512).digest()
    Il, Ir = I[:32], I[32:]
    k_child = (int.from_bytes(Il, "big") + int.from_bytes(parent_k, "big")) % SECP256K1_ORDER
    return k_child.to_bytes(32, "big"), Ir

def pubkey_to_address(pubkey: bytes) -> str:
    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return base58.b58encode_check(b"\x00" + ripe).decode("utf-8")

def derive_address(seed: bytes, path: str, compressed: bool = True) -> str:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for step in path.split("/")[1:]:
        hardened = step.endswith("'") or step.endswith("h")
        idx = int(step[:-1]) + 0x80000000 if hardened else int(step)
        k, c = ckd_priv(k, c, idx)
    pub = get_pubkey(k, compressed=compressed)
    return pubkey_to_address(pub)

def is_valid_bip39(words: list[str], word_to_idx: dict[str, int]) -> bool:
    n = len(words)
    if n not in (12, 24):
        return False
    bits = "".join(f"{word_to_idx[w]:011b}" for w in words)
    ent_len = 128 if n == 12 else 256
    cs_len = 4 if n == 12 else 8
    ent_bytes = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    h = hashlib.sha256(ent_bytes).digest()
    expected_cs = f"{h[0]:08b}"[:cs_len]
    return bits[ent_len:] == expected_cs

def main():
    print(f"Целевой биткоин-адрес: {TARGET_ADDRESS}")
    print("-" * 60)

    # 1. Загрузка BIP-39 словаря
    if not WORDS_FILE.exists():
        print(f"Файл {WORDS_FILE} не найден!")
        return
    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        bip_words = [line.strip().lower() for line in f if line.strip()]
    word_to_idx = {w: i for i, w in enumerate(bip_words)}
    print(f"Загружен словарь BIP-39: {len(bip_words)} слов")

    # 2. Загрузка найденных слов
    if not FOUND_WORDS_FILE.exists():
        print(f"Файл {FOUND_WORDS_FILE} не найден! Сначала запустите find_words.py")
        return
    with open(FOUND_WORDS_FILE, "r", encoding="utf-8") as f:
        found_words = [line.strip().lower() for line in f if line.strip()]
    print(f"Загружено слов из found_words.txt: {len(found_words)}")
    print("-" * 60)

    found_solution = False

    # 3. Проверка для 12 и 24 слов
    for length in [12, 24]:
        total_windows = len(found_words) - length + 1
        print(f"\n[+] Проверка блоков по {length} слов (всего комбинаций: {total_windows})...")
        valid_checksum_count = 0

        for i in range(total_windows):
            window = found_words[i : i + length]
            
            # Проверяем контрольную сумму BIP-39
            if not is_valid_bip39(window, word_to_idx):
                continue

            valid_checksum_count += 1
            mnemonic = " ".join(window)

            # Вычисляем сид
            seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048)

            # Проверяем по разным путям деривации
            for path in DERIVATION_PATHS:
                for comp in [True, False]:
                    addr = derive_address(seed, path, compressed=comp)
                    if addr == TARGET_ADDRESS:
                        print("\n" + "=" * 60)
                        print("🎉 УРА! НАЙДЕНА ВАЛИДНАЯ СИД-ФРАЗА КОШЕЛЬКА!")
                        print(f"Длина: {length} слов")
                        print(f"Смещение в тексте (слово №): {i + 1}")
                        print(f"Сид-фраза: {mnemonic}")
                        print(f"Путь деривации: {path} (сжатый ключ: {comp})")
                        print("=" * 60)
                        found_solution = True
                        return

        print(f"Проверено. Найдено фраз с валидной контрольной суммой: {valid_checksum_count}")

    if not found_solution:
        print("\n" + "-" * 60)
        print("Результат: Среди последовательных блоков слов из текста прямого совпадения с пустым паролем не найдено.")
        print("Подсказка: В статье автор упомянул Trithemian Seeds (где слова выбираются по координатам или номерам телефонов, а не просто подряд).")

if __name__ == "__main__":
    main()
