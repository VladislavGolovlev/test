import email
from bs4 import BeautifulSoup

with open('Trithemius_Coinmonks_Medium.mhtml', 'rb') as f:
    msg = email.message_from_binary_file(f)

html_part = None
images = []
for part in msg.walk():
    ct = part.get_content_type()
    if ct == 'text/html' and not html_part:
        html_part = part.get_payload(decode=True).decode('utf-8', errors='ignore')
    elif 'image' in ct:
        images.append((part.get_param('name') or part.get('Content-Location', ''), len(part.get_payload(decode=True) or b'')))

print(f'HTML length: {len(html_part) if html_part else 0}')
print(f'Total images embedded: {len(images)}')
for name, sz in images:
    print(f'Image: {name[:80]} (size {sz} bytes)')

soup = BeautifulSoup(html_part, 'html.parser')

print('\n--- ALL IMAGES ALT & CAPTIONS ---')
for img in soup.find_all('img'):
    alt = img.get('alt', '')
    src = img.get('src', '')
    parent_fig = img.find_parent('figure')
    cap = parent_fig.find('figcaption').get_text(strip=True) if parent_fig and parent_fig.find('figcaption') else ''
    print(f'IMG alt: "{alt}" | Caption: "{cap}"')

print('\n--- EXTERNAL LINKS ---')
for a in soup.find_all('a', href=True):
    href = a['href']
    txt = a.get_text(strip=True)
    if 'medium.com' not in href and not href.startswith('#') and not href.startswith('javascript'):
        print(f'Link: "{txt}" -> {href}')

print('\n--- MEDIUM LINKS & PROFILES ---')
for a in soup.find_all('a', href=True):
    href = a['href']
    txt = a.get_text(strip=True)
    if '@' in href or 'trithemius' in href.lower():
        print(f'Author/User Link: "{txt}" -> {href}')

print('\n--- META TAGS ---')
for m in soup.find_all('meta'):
    name = m.get('name') or m.get('property')
    content = m.get('content')
    if name and content:
        print(f'{name}: {content[:100]}')

with open('extracted_medium_html.html', 'w', encoding='utf-8') as f:
    f.write(html_part)
print('\nSaved extracted HTML to extracted_medium_html.html')
