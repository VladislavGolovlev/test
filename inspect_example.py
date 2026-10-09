import re

text = """Such an asset to be represented by an experienced and mature lawyer particularly when you have a trial in front of the Supreme Court of the USA. Load your argument with logic and do not provide ways to escape. Symbol of cultural diversity should be used as often as possible in order to support the story. Our client clearly did not make that complex and improvised bomb himself. They were on their way to his friend's picnic by the river when he noticed a suspicious person pretending to do aerobic exercises. He immediately pointed it out to his friends. Their whereabouts aren't a mystery, during the attack they were ordering ginger tea with honey to bring to the picnic."""

indices = [3, 18, 28, 39, 40, 56, 67, 77, 80, 90, 104, 114]

with open("word.txt", "r", encoding="utf-8") as f:
    bip_words = set(w.strip().lower() for w in f if w.strip())

# 1. Whitespace split with punctuation strip
words_ws = [re.sub(r"^[^\w]+|[^\w]+$", "", w).lower() for w in text.split()]

print("--- WHITESPACE SPLIT ---")
print(f"Total words: {len(words_ws)}")
extracted_ws = []
for idx in indices:
    w = words_ws[idx - 1] if idx - 1 < len(words_ws) else "OUT_OF_BOUNDS"
    in_bip = w in bip_words
    extracted_ws.append(w)
    print(f"Index {idx:3d}: '{w}' (in BIP-39: {in_bip})")

print("\nResult phrase (WS):", " ".join(extracted_ws))

# 2. Regex word split
words_re = [w.lower() for w in re.findall(r"\b[A-Za-z0-9'-]+\b", text)]
print("\n--- REGEX SPLIT ---")
print(f"Total words: {len(words_re)}")
extracted_re = []
for idx in indices:
    w = words_re[idx - 1] if idx - 1 < len(words_re) else "OUT_OF_BOUNDS"
    in_bip = w in bip_words
    extracted_re.append(w)
    print(f"Index {idx:3d}: '{w}' (in BIP-39: {in_bip})")

print("\nResult phrase (RE):", " ".join(extracted_re))
