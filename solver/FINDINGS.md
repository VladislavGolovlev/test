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
printed list. Its example is *not* rigorous — it yields 11/12 BIP39 words (only
`a`, at position 113, is absent; `payment` **is** a BIP39 word — see §8),
consistent with the method's own stated use of "true and decoy seed phrases".

### The decisive structural consequence

Because `position_j = digit_j + 10*j` and `digit_j ∈ [0,9]`, **seed word *j*
must be a wordlist word inside the decade window `[10j, 10j+9]`**. This makes
the search *coordinate-agnostic*: enumerating all decade-consistent
combinations covers **every possible landmark on Earth** at once, with no need
to guess coordinates. That is the basis of `final.py`.

---

## 2. A text-extraction bug in THIS repository's analysis

> **Corrected (SS8):** this bug was in this repository's own `analyze_mhtml.py`,
> NOT in the community's work. HomelessPhD/Wealth_in_Poetry's `text.txt` has all
> seven `ye-ye` spaces intact, so this does not explain six years of failure.

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

1. ~~**The GPS method is exhausted.**~~ **WRONG -- see SS8.** The decade
   constraint is coordinate-agnostic but NOT carrier-start-agnostic, and the
   free enumeration swept story-start offsets 0-30 only, i.e. just the first
   ~149 tokens of each carrier as a starting point (~6% of the article). What
   *is* established is narrower: no reading from a real landmark's coordinates,
   indexed into the RAW token stream at offsets 0-5, yields 12 valid words
   anywhere in the article except the published example.
2. **The phone method has no recoverable key.** The article states the numbers
   "should be written on a different page to remove any connection between the
   text and the numbers", and no hidden ascending number sequence exists in the
   article. Note the hint's exact wording — "you've read every **word**
   required" — which promises the *words*, never the numbers.

A first reading of this was that the puzzle is **underdetermined as published**
(below). SS8 shows that conclusion was premature, because it rested on the
retracted exhaustion claim:
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

---

## 8. Corrections from an adversarial audit

Four independent agents were tasked with attacking the claims above. They found
real errors. These corrections supersede the text where they conflict.

### Retracted: "the GPS method is exhausted" (§5)

**The most serious error.** The decade constraint is coordinate-agnostic, but
**not carrier-start-agnostic**: the article's rule gives absolute positions from
word 1 of the carrier, so *where the carrier begins* is a free parameter.
`final.py` swept story-start offsets 0–30 only, and since position 11 is
`off + 119`, it only ever read tokens 1–149 of each stream — about **6% of the
article's 2,490 tokens** as a starting point. The GPS method is **not**
exhausted.

What survives is narrower and still useful: no reading taken from a *real
landmark's* coordinates, indexed into the **raw** token stream at offsets 0–5,
yields 12 valid words anywhere in the article except the published example.

The audit also extended coverage, all with no hit:
* Revolution-story family (5 carriers × 8 tokenizations), free decade
  enumeration at **all** offsets: 11,351,708 readings → 45,172 unique
  checksum-valid mnemonics → 4,246,168 address checks.
* The same carriers at **15 words**: 19,017,732 readings → 77,850 unique
  checksum-valid seeds. **18 words** enumerated (306,627 candidates), partially
  derived.
* Landmark coordinates indexed into the **wordlist-filtered subsequence** (a
  gap — the sweeps in §4 indexed only the raw stream) at lengths 12/15/18/24:
  13,189,512 readings → 25,922 candidates.

### Retracted: the extraction bug "invalidated earlier attempts" (§2)

The bug is real, but it was in **this repository's** `analyze_mhtml.py`, not in
the community's work. The audit cloned HomelessPhD/Wealth_in_Poetry and checked
`python_script/text.txt`: all seven `ye-ye` occurrences have their surrounding
spaces intact. So it does **not** explain six years of failure. (Also: that
repo's `.mhtml` and this one's are byte-identical — same Blink MIME boundary,
same Content-ID, same `Date: Tue, 15 Aug 2023`. There is only one capture, so
no cross-check of the article text against a second source was actually made.)

### Factual fix: `payment` IS a BIP39 word

It is at index 1293. So the phone example's published reading is **11/12**
BIP39 words, not 10/12 — only `a` (position 113) is absent. Position 114 holds
`good`, a BIP39 word, so the published reading misses by a single position;
but the author's own digits (`…011–3116` → 100, 113, 116) do give 113, so there
is no off-by-one to exploit. The reading is a decoy or simply sloppy.

### Undocumented caps silently dropped work

Both enumerators abandoned any offset whose combination count exceeded a hard
cap, with no log line and no counter (`final.py`: `if tot > 4_000_000`;
`elecgen.py`: `if tot > 60000`). For the Electrum run this is severe: 80
(carrier × tokenization × offset) jobs were skipped covering 18,528,960
combinations against 7,923,160 actually enumerated, so roughly **70% of even
the offsets 0–15 range went unscanned**. The "402,949 candidates" row in §4
therefore covers far less than it implies.

### Derivation coverage was lopsided

The 4,250 checksum-valid decade candidates — the set produced by the article's
*own documented method* — were tested against only **5** derivation paths,
versus 10,657 paths for each of the three printed phrases: a 2,000× asymmetry
applied to exactly the wrong set. The Electrum-v2 KDF (PBKDF2-HMAC-SHA512, salt
`electrum`) was never applied to them either.

### The checksum filter is an assumption, not a certainty

Every BIP39 sweep filters on a valid checksum, which assumes the author's seed
is a well-formed mnemonic. He demonstrably published a **non**-BIP39 phrase
while calling it "BIP-39", so he was not careful about this. Dropping the filter
multiplies the space by 16 — expensive, but it is an assumption worth recording.

### Smaller items

* The GPU README's "2,863,703,783 candidates" is **offset-summed** and
  double-counts: a position tuple is decade-consistent for a contiguous range
  of offsets, so distinct candidates are ~25–30% fewer.
* "~60 carrier texts" (§4 preamble) describes `twotests.py`/`elecgen.py`;
  `final.py` — the authoritative BIP39 decade solver — defines 10 streams and
  no per-paragraph carriers.
* §3's "structurally incapable under BIP39" holds **only at offset 0**. At
  offsets 1, 2 and 3 the `body`, `p_only` and Revolution-story carriers are all
  feasible (every decade window populated). This weakens the §7 inference that
  the carrier *must* be purpose-written — the phone-method hypothesis rests on
  density and on the method's own off-page key, not on impossibility.
* `word.txt` is byte-for-byte 13,115 bytes with no trailing newline, so it
  hashes to `187db04a…`; the canonical `2f5eed53…` matches only after
  canonicalising to `'\n'.join(words)+'\n'`. The 2048 words themselves are
  confirmed identical to the official list.
* The phone example has **two** distinct readings across tokenization variants
  (not one): its standalone ASCII hyphen in "the courtyard - no adult" becomes
  a token when punctuation-only tokens are kept, shifting later positions.

### Status after the audit

"The puzzle is underdetermined as published" (§5) was **premature** — it rested
on the retracted exhaustion claim. The GPS offset space is largely untouched,
and the Electrum space is ~70% unscanned even where it was reported as covered.
