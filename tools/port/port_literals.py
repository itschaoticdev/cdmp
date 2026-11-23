"""port_literals.py OLD.exe NEW.exe 0xRVA [0xRVA ...]

Carries RVAs hardcoded outside offsets.h (mid-function hook sites, direct calls,
globals, vtables) from OLD to NEW. Uses the .pdata function table:
  code   -> port the containing function's prologue (cd_port.port_function),
            then find the site inside the new function by its own masked bytes
  vtable -> RTTI (cd_port.port_vtable)
  global -> RIP-reference votes (cd_port.port_global)
"""
import bisect, struct, sys, importlib.util, os

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cd_port", os.path.join(here, "cd_port.py"))
cp = importlib.util.module_from_spec(spec); spec.loader.exec_module(cp)


def functions(img):
    """Sorted (begin, end) from the exception directory."""
    d = img.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    out = []
    for i in range(d.Size // 12):
        at = d.VirtualAddress + 12 * i
        if at + 12 > len(img.img): break   # the table can run past the mapped image
        b, e, _ = struct.unpack_from("<III", img.img, at)
        if b < e: out.append((b, e))
    out.sort()
    return out


def cc_bounds(img, rva):
    """Function around rva from the int3 padding (fallback when .pdata misses it)."""
    m = img.img; s = rva
    while s > 2 and not (m[s - 1] == 0xCC and m[s - 2] == 0xCC): s -= 1
    e = rva
    while e < len(m) - 2 and not (m[e] == 0xCC and m[e + 1] == 0xCC): e += 1
    return (s, e)


IMG = {}
def containing(funcs, starts, rva):
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0 and funcs[i][0] <= rva < funcs[i][1]: return funcs[i]
    return cc_bounds(IMG[id(funcs)], rva)


def in_code(img, rva): return any(a <= rva < b for a, b in img.code)


def port_site(old, new, of, nf, ostarts, nstarts, rva):
    fn = containing(of, ostarts, rva)
    if not fn: return None, "no .pdata function in OLD"
    nstart, how = cp.port_function(old, new, fn[0])
    if nstart is None: return None, f"function 0x{fn[0]:X}: {how}"
    if rva == fn[0]: return nstart, f"function start; {how}"
    nfn = containing(nf, nstarts, nstart) or (nstart, nstart + (fn[1] - fn[0]) + 0x400)
    body = bytes(new.img[nfn[0]:nfn[1]])
    for n in (16, 24, 40, 64, 96):
        pat, msk = cp.masked(old, rva, n)
        hits = [nfn[0] + m.start() for m in cp.regex(pat, msk).finditer(body)]
        if len(hits) == 1:
            same = "same offset" if hits[0] - nstart == rva - fn[0] else f"offset +0x{rva - fn[0]:X} -> +0x{hits[0] - nstart:X}"
            return hits[0], f"+0x{rva - fn[0]:X} in 0x{fn[0]:X} -> 0x{nstart:X} ({how}); site {len(pat)} B unique, {same}"
        if not hits: return None, f"site bytes ({len(pat)} B) not found in new function 0x{nstart:X}"
    return None, "site still ambiguous inside the new function"


def main():
    old, new = cp.Image(sys.argv[1]), cp.Image(sys.argv[2])
    of, nf = functions(old), functions(new)
    IMG[id(of)], IMG[id(nf)] = old, new
    ostarts, nstarts = [a for a, _ in of], [a for a, _ in nf]
    for arg in sys.argv[3:]:
        rva = int(arg, 16)
        if in_code(old, rva):
            v, how = port_site(old, new, of, nf, ostarts, nstarts, rva)
        else:
            v, how = cp.port_vtable(old, new, rva)
            if v is None:
                v2, how2 = cp.port_global(old, new, rva)
                if v2 is not None: v, how = v2, "global " + how2
                else: how = f"{how}; global: {how2}"
        print(f"0x{rva:X} -> {('0x%X' % v) if v is not None else '-':>10}  {how}")


if __name__ == "__main__":
    main()
