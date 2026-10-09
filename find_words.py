import re
import sys
from pathlib import Path

# Обеспечиваем корректный вывод русского текста в консоли Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Пути к файлам
FILE_TEXT = Path(r"c:\Users\Vladislav\Desktop\Новая папка\Текстовый документ (2).txt")
FILE_WORDS = Path(r"c:\Users\Vladislav\Desktop\Новая папка\word.txt")
OUTPUT_FILE = Path(r"c:\Users\Vladislav\Desktop\Новая папка\found_words.txt")

def main():
    # 1. Загружаем словарь (слова в нижнем регистре для быстрого поиска O(1))
    if not FILE_WORDS.exists():
        print(f"Ошибка: файл словаря не найден: {FILE_WORDS}")
        return

    with open(FILE_WORDS, "r", encoding="utf-8") as f:
        dictionary = set(line.strip().lower() for line in f if line.strip())

    print(f"Загружено слов из словаря: {len(dictionary)}")

    # 2. Читаем исходный текст
    if not FILE_TEXT.exists():
        print(f"Ошибка: текстовый файл не найден: {FILE_TEXT}")
        return

    with open(FILE_TEXT, "r", encoding="utf-8") as f:
        text = f.read()

    # 3. Извлекаем слова последовательно (очищая от знаков препинания)
    words = re.findall(r"[a-zA-Z]+", text)
    print(f"Всего слов в первом файле: {len(words)}")
    print("-" * 50)
    print("Найденные слова в порядке следования в тексте:\n")

    matched_words = []
    index = 1
    for word in words:
        clean_word = word.lower()
        if clean_word in dictionary:
            matched_words.append(clean_word)
            print(f"{index:4d}. {clean_word} (исходное: '{word}')")
            index += 1

    # 4. Сохраняем результат в отдельный файл для удобства
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for w in matched_words:
            f.write(w + "\n")

    print("-" * 50)
    print(f"Готово! Всего найдено совпадений: {len(matched_words)}")
    print(f"Список слов сохранён в файл: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
