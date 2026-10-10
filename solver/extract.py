import re, json
from bs4 import BeautifulSoup

h = open('/home/user/test/extracted_medium_html.html', encoding='utf-8').read()
soup = BeautifulSoup(h, 'html.parser')

art = soup.find('article') or soup
blocks = []
for el in art.find_all(['h1','h2','h3','p','pre','blockquote','figcaption','li']):
    # skip nested duplicates (p inside blockquote etc.)
    if el.find_parent('blockquote') and el.name == 'p':
        continue
    t = el.get_text()                     # NO strip=True -> keeps inline spacing
    t = t.replace(' ', ' ')
    t = re.sub(r'\s+', ' ', t).strip()
    if t:
        blocks.append({'tag': el.name, 'text': t, 'id': el.get('id','')})

# drop UI chrome / duplicates
seen = set()
clean = []
UI = {'Follow','Listen','Share','Coinmonks','Trithemius','Sign up','Sign in','Write',
      'Trithemius','--','Help','Status','About','Careers','Press','Blog','Privacy','Terms','Text to speech','Teams'}
for b in blocks:
    if b['text'] in UI or re.fullmatch(r'[\d\s.KMk]+', b['text']):
        continue
    key = (b['tag'], b['text'])
    if key in seen:
        continue
    seen.add(key)
    clean.append(b)

with open('blocks.json','w') as f:
    json.dump(clean, f, indent=1, ensure_ascii=False)

for i,b in enumerate(clean):
    print(f"[{i}] <{b['tag']}> {b['text'][:150]}")
