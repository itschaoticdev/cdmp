"""port_by_callers.py OLD.exe NEW.exe 0xRVA [...]
For a function whose own prologue can't be matched: find direct calls to it in
OLD, carry each call site to NEW (port_literals.port_site), and read the call
target there. Callers that agree vote."""
import sys, struct, collections, numpy as np, importlib.util, os
here = os.path.dirname(os.path.abspath(__file__))
def load(n):
    s = importlib.util.spec_from_file_location(n, os.path.join(here, n + ".py")); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
pl = load("port_literals"); cp = pl.cp

def call_sites(img, target, cap=30):
    lo, text = img.text(); a = np.frombuffer(text, dtype=np.uint8); out = []
    for k in range(4):
        m = (len(a) - 1 - k) // 4
        d32 = np.frombuffer(text, dtype="<i4", count=m, offset=1 + k)
        for c0 in range(0, m, 1 << 24):
            d = d32[c0:c0 + (1 << 24)].astype(np.int64); p = 1 + k + 4 * (c0 + np.arange(len(d), dtype=np.int64))
            ok = d == target - lo - 4 - p
            for q in p[ok]:
                if text[q - 1] == 0xE8: out.append(lo + int(q) - 1)
    return sorted(out)[:cap]

old, new = cp.Image(sys.argv[1]), cp.Image(sys.argv[2])
of, nf = pl.functions(old), pl.functions(new); pl.IMG[id(of)], pl.IMG[id(nf)] = old, new
os_, ns_ = [a for a, _ in of], [a for a, _ in nf]
for arg in sys.argv[3:]:
    t = int(arg, 16); votes = collections.Counter(); sites = call_sites(old, t)
    for s in sites:
        ns, how = pl.port_site(old, new, of, nf, os_, ns_, s)
        if ns is None or new.img[ns] != 0xE8: continue
        votes[ns + 5 + struct.unpack_from("<i", new.img, ns + 1)[0]] += 1
    best = votes.most_common(3)
    print(f"0x{t:X}: {len(sites)} callers, votes {[(hex(v), n) for v, n in best]}")
