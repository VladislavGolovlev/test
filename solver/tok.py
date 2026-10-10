import re, sys
sys.path.insert(0,'.')
import btclib as B

APOS = '’'
def normalize(t):
    return (t.replace('‘',"'").replace('’',"'")
             .replace('“','"').replace('”','"')
             .replace('–','-').replace('—','—'))

STRIP_RE = re.compile(r"^[^A-Za-z0-9']+|[^A-Za-z0-9']+$")

def tokenize(text, drop_punct_only=True, split_hyphen=False, keep_numbers=True):
    text = normalize(text)
    raw = text.split()
    toks = []
    for w in raw:
        if split_hyphen and '-' in w:
            parts = [p for p in w.split('-') if p]
        else:
            parts = [w]
        for p in parts:
            c = STRIP_RE.sub('', p)
            if c == '' :
                if not drop_punct_only:
                    toks.append('')
                continue
            if not keep_numbers and re.fullmatch(r"[0-9']+", c):
                continue
            toks.append(c)
    return toks

def word_at(toks, pos):
    if 1 <= pos <= len(toks):
        return toks[pos-1].lower().strip("'")
    return None
