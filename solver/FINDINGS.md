# "Securing Wealth in Poetry" — analysis of the 0.03 BTC Trithemian-seed puzzle

Target address: `1K4ezpLybootYF23TM4a8Y4NyP7auysnRo`
Article: Trithemius, *Securing Wealth in Poetry*, Coinmonks / Medium, 2019-02-11.

This document records what has been **established as fact** (with reproducible
code), what has been **ruled out exhaustively**, and what remains open. It is
written so nothing here has to be re-derived.

---

## 1. The algorithm is known and verified

The article documents two methods. The **"Letter & GPS location"** method is
fully specified and reproducible:

> every digit read increases by ten, so 21.493021 translates to:
> 2, 11, 24, 39, 43, 50, 62, 71

Formally, for the *j*-th digit (0-indexed) of the landmark's coordinates:

```
position_j = digit_j + 10 * j        (1-indexed word position in the carrier text)
```

**Verified** against the article's own worked example. `U.S. Supreme Court:
38.8906° N, 77.0044° W` gives digits `3,8,8,9,0,6,7,7,0,0,4,4`, hence positions
`3,18,28,39,40,56,67,77,80,90,104,114` — exactly the list the article prints.
Reading those words out of the example text yields:

```
asset trial load escape symbol story bomb picnic river aerobic mystery honey
```

All 12 are BIP39 words **and the BIP39 checksum is valid** (a 1-in-16 event by
chance), so this is a genuine, deliberately constructed mnemonic. Tokenization
is plain whitespace splitting with surrounding punctuation stripped; the result
is stable under every tokenization variant tried.

The **"Story & phone number"** method derives its positions by reading the
concatenated phone digits as a greedy ascending sequence: `+26-918-222-5457` /
`+08-610-011-3116` → `2,6,9,18,22,25,45,70,86,100,113,116`, again exactly the
printed list. Its example is *not* rigorous — it yields only 10/12 BIP39 words
(`a` and `payment` are not BIP39), consistent with the method's own stated use
of "true and decoy seed phrases".

### The decisive structural consequence

Because `position_j = digit_j + 10*j` and `digit_j ∈ [0,9]`, **seed word *j*
must be a wordlist word inside the decade window `[10j, 10j+9]`**. This makes
the search *coordinate-agnostic*: enumerating all decade-consistent
combinations covers **every possible landmark on Earth** at once, with no need
to guess coordinates. That is the basis of `final.py`.

---

## 2. A text-extraction bug that invalidated earlier attempts

Earlier work extracted the article with `BeautifulSoup.get_text(strip=True)`,
which **destroys the spaces around inline `<em>` tags**:

```
HTML:      my <em>ye-ye</em> grew      (3 words)
extracted: myye-yegrew                 (1 word)   <-- shifts every later position
```

The article contains 7 such inline spans, so every word position after the
first one was wrong. Since this method is purely positional, that alone
guarantees failure. `extract.py` fixes it; `article_blocks.json` is the
corrected block-level text. The corrected extraction also recovers a paragraph
missing from earlier dumps — the one naming the address and the
end-of-2020 donation pledge.

---

## 3. The article's printed "Seed Phrase" is an **old Electrum** seed, not BIP39

```
witch collapse practice feed shame open despair creek road again ice least
```

`witch`, `collapse`, `shame` and `least` are **not** in the BIP39 English
wordlist (verified: our wordlist is the official 2048-word list, sha256
`2f5eed53…dbda`, sorted, unique 4-char prefixes). All 12 words **are** in the
1626-word **old Electrum (v1)** list.

This matters: it is direct evidence the author was working with Electrum, and
it reframes the whole puzzle, since six years of community attempts assumed
BIP39. `elec1.py` implements Electrum v1 and is **verified exactly** against
Electrum's own test vector (seed `powerful random nobody … over` → mpk
`e9d4b786…42b3`, address 0 `1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo`).

Crucially, under BIP39 the article's prose is **structurally incapable** of
carrying a GPS-embedded seed — some decade windows contain no BIP39 word at all
(e.g. words 1–9 of the Revolution story: *My grandfather known to me as ye-ye
was born* — none are BIP39). Under the Electrum wordlist the same text **is**
feasible (every decade window populated; 4320 combinations at offset 0).

---

## 4. What has been ruled out

All searches below used the corrected extraction, 8 tokenization variants
(punctuation-only tokens kept/dropped, hyphenated words split/kept, numerals
kept/dropped), ~60 carrier texts (whole article, body, sections, the Revolution
story, every individual paragraph), and legacy P2PKH addresses in both
compressed and uncompressed form.

| Search | Scope | Result |
|---|---|---|
| GPS decade enumeration, BIP39 | 80 carrier×tokenization configs, story-start offsets 0–30; 4,250 checksum-valid seeds × 5 derivation paths | no match |
| Real landmark coordinates, BIP39 | 34 landmarks named/implied in the article × 36 decimal renderings × all carriers × offsets 0–5 = **91,776 readings** | **only** the published Supreme Court example yields 12 BIP39 words anywhere in the article |
| Real landmark coordinates, Electrum | 37 landmarks, same sweep | **zero** readings yield 12 Electrum words |
| Published number lists applied elsewhere | both printed lists × all carriers × raw and BIP39-filtered indexing × offsets | no match (correctly re-finds the example itself) |
| Contiguous 12-windows over the ordered wordlist subsequence (the community approach, redone correctly) | 745 unique BIP39 windows; 611 Electrum windows | no match |
| The three explicit phrases in the article | GPS example, phone-list reading, printed seed phrase | no match across **10,657 derivation paths** each (BIP44 accounts 0–20 × chains × indices 0–200, bare `m/i`, `m/0'/0/i`, `m/0'/0'/i`, Electrum-v2 seed derivation, brainwallet SHA256) |
| Hidden number pair in the article | all 83 integers extracted in order | the **only** ascending 12-number sequences in the whole article are the two published example lists — there is no third, hidden one |
| Image steganography | all 14 embedded images: EXIF (incl. GPS), XMP, trailing bytes after EOF, embedded strings | nothing; Medium re-encoded every image to WebP, so any pixel payload was destroyed at publication regardless |
| Formatting "plain sight" channel | every `<em>`, `<strong>`, `<a>`, `<code>` span | no 12-word pattern |
| Old Electrum v1 | 402,949 candidates: published lists + contiguous windows + free decade enumeration at offsets 0–15, all carriers/tokenizations; each seed stretched (100k SHA256) and checked at 20 addresses (indices 0–4 x change 0/1 x compressed/uncompressed) plus the master key itself | **no match** (4,418 s) |

---

## 5. Assessment

Two findings constrain the puzzle hard:

1. **The GPS method is exhausted.** Because the decade constraint is
   coordinate-agnostic, and because no landmark reading anywhere in the article
   produces 12 valid words in either wordlist except the published example,
   there is no *second* GPS-embedded seed in the article's text.
2. **The phone method has no recoverable key.** The article states the numbers
   "should be written on a different page to remove any connection between the
   text and the numbers", and no hidden ascending number sequence exists in the
   article. Note the hint's exact wording — "you've read every **word**
   required" — which promises the *words*, never the numbers.

So the likely situation is that the puzzle is **underdetermined as published**:
the carrier words are present but the positional key is not, leaving a search
space of C(582,12) ≈ 2.8×10²⁴ ordered selections. The Electrum v1 avenue has now also been run over every structurally feasible
carrier at story-start offsets (402,949 candidates, no match). Electrum v1 key
stretching costs 100,000 SHA256 rounds (~44 ms/seed, ~90 seeds/s on 4 cores),
so it cannot be brute-forced beyond that without a large compute budget: the
remaining offsets across all carriers are ~10-50M candidates, i.e. days of CPU.

**Before spending more compute, check whether the address still holds funds.**
The article pledged to donate the balance to GiveDirectly if it was not claimed
by the end of 2020. This environment's network policy blocks every block
explorer, so it could not be checked here.

---

## 6. Files

| File | Purpose |
|---|---|
| `extract.py` | correct article extraction → `article_blocks.json` |
| `tok.py` | tokenization variants |
| `btclib.py` | BIP32/BIP39 → legacy P2PKH (verified against the standard BIP39 test vector) |
| `elec1.py` | old Electrum v1 wallet (verified against Electrum's test vector) |
| `final.py` | coordinate-agnostic GPS decade solver, BIP39, parallel |
| `twotests.py` | contiguous-window and real-landmark sweeps |
| `elecgen.py` / `eleccheck.py` | Electrum candidate generation and address checking |

All of it is reproducible: `python3 extract.py` then any of the solvers.

---

## 7. Correction and a stronger hypothesis (from a reader's comment)

A commenter on the article asked what conversion links the article's two
printed examples -- the hex private key
`E9873D79…3AA33262` and the seed phrase `witch collapse practice feed shame
open despair creek road again ice least` -- saying their own attempts gave
different results.

**Answer: there is no conversion.** Tested and refuted: Electrum v1
`mnemonic_decode` (gives `25a39767960aafbdba67ad41f5657826`), the full v1
stretch, stretching the phrase text itself, SHA256/SHA256d/SHA512 of the phrase
in six spellings, PBKDF2/BIP39 seed halves and BIP32 master, and Electrum v2.
The two examples are unrelated stock samples. GitHub code search finds that
phrase in **309 files** (wallet placeholder text, docs, tutorials).

### This corrects §3

Because the phrase is a stock example the author pasted, its being
Electrum-wordlist-only is **weak** evidence about his own tooling. §3 overstated
that inference, and the Electrum v1 avenue is less well-motivated than it
claimed (it remains untested at scale, hence `gpu/`, but it is no longer the
leading hypothesis).

### And it points the other way

The evidence about the author's *own* tooling is the GPS example, which he
constructed himself: it decodes to a 12-word BIP39 mnemonic with a **valid
checksum** (1-in-16 by chance). So he used BIP39. Combined with §3's structural
result -- that BIP39 is impossible in the article's *prose* because some decade
windows hold no BIP39 word -- the carrier must be a **purpose-written** text.
The only purpose-written texts are the two worked examples, and their BIP39
density confirms it:

| text | tokens | BIP39 words | density |
|---|---|---|---|
| phone example | 123 | 51 | **41%** |
| GPS example | 119 | 37 | 31% |
| Revolution story (natural prose) | 596 | 112 | 19% |

The phone example is the prime suspect: it is the densest, the method states it
contains "true and decoy seed phrases", and its own published numbers decode to
an **invalid** phrase (`a` and `payment` are not BIP39) -- i.e. the published
reading is a decoy.

Critically, the phone method keeps its key off the page by design -- "These
should be written on a different page to remove any connection between the text
and the numbers" -- so brute-forcing the positions is the intended-difficulty
path, and the hint's wording fits exactly: it promises every **word**, never
the numbers.

### The prune

Positions are a greedy ascending read of the concatenated phone digits, so the
12 positions' **total digit count** equals the digits of 2-3 phone numbers.
Verified on the published example: `2,6,9,18,22,25,45,70,86,100,113,116` has
digit-lengths `1,1,1,2,2,2,2,2,2,3,3,3` = 24 = two 12-digit numbers. Requiring
a three-phone-number profile prunes the space **165x**.

| carrier | slice | combos | checksum-valid | 4-core CPU |
|---|---|---|---|---|
| GPS example | 3 phones (30-39 digits) | 9,238,671 | 577,417 | ~0.6 h |
| GPS example | 24 digits | 214,526,520 | 13,407,908 | ~1.2 h |
| GPS example | 2 phones (20-26 digits) | 1,208,613,315 | 75,538,332 | ~6.8 h |
| phone example | 3 phones (30-39 digits) | 958,995,275 | 59,937,205 | ~5.4 h |
| phone example | 24 digits (as published) | 26,640,902,470 | 1,665,056,404 | ~150 h (GPU) |
| phone example | 2 phones (20-26 digits) | 117,873,413,580 | 7,367,088,349 | ~896 h (GPU) |

`subset_phone.py` implements this. Its enumerator is validated end-to-end: it
reproduces the known-good GPS reading exactly (profile (1,9,2), 25 digits), and
each slice's task decomposition is checked to cover exactly the expected
combinatorial count.
