"""Derive old-Electrum (v1) addresses for every candidate phrase and compare
against the puzzle address.  Master-key stretching (100k SHA256) dominates, so
each seed is stretched once and then many address indices are checked cheaply.
"""
import sys, os, time
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elec1, btclib as B

TARGET = '1K4ezpLybootYF23TM4a8Y4NyP7auysnRo'
HERE = os.path.dirname(os.path.abspath(__file__))
NADDR = 5            # address indices per change branch
CHANGES = (0, 1)


def work(item):
    mn, prov = item
    words = mn.split()
    hs = elec1.mnemonic_decode(words)
    if hs is None:
        return None
    msec, mpk = elec1.master_from_seed(hs)
    for c in CHANGES:
        for n in range(NADDR):
            for comp in (False, True):
                if elec1.address_at(msec, mpk, n, c, comp) == TARGET:
                    return (mn, prov, hs, c, n, comp)
    # also treat the stretched key itself as a plain private key
    for comp in (False, True):
        if B.addr_p2pkh(B.pub_from_priv(msec.to_bytes(32, 'big'), comp)) == TARGET:
            return (mn, prov, hs, 'master', -1, comp)
    return None


def main():
    rows = []
    with open(os.path.join(HERE, 'elec_cands.txt')) as f:
        for line in f:
            mn, _, prov = line.rstrip('\n').partition('\t')
            if mn:
                rows.append((mn, prov))
    order = {'B': 0, 'C': 1, 'A': 2, 'D': 3}
    rows.sort(key=lambda r: order.get(r[1].split('|')[0], 9))
    print(f'candidates: {len(rows):,}', flush=True)
    t0 = time.time()
    hits = []
    with Pool(4) as pool:
        for i, r in enumerate(pool.imap(work, rows, chunksize=8)):
            if r:
                hits.append(r)
                print('\n*** ADDRESS MATCH ***', r, flush=True)
            if i % 2000 == 0 and i:
                el = time.time() - t0
                rate = i / el
                print(f'  {i:,}/{len(rows):,} [{el:.0f}s, {rate:.0f}/s, '
                      f'eta {(len(rows)-i)/rate/60:.0f}m] hits={len(hits)}', flush=True)
    print(f'DONE checked={len(rows):,} hits={len(hits)} elapsed={time.time()-t0:.0f}s', flush=True)
    if hits:
        with open(os.path.join(HERE, 'ELECTRUM_HIT.txt'), 'w') as f:
            for h in hits:
                f.write(repr(h) + '\n')


if __name__ == '__main__':
    main()
