"""test_port.py OLD.dll NEW.dll - measure cd_port against ground truth from two builds of one DLL.
functions: exported function RVAs by name. globals: the first RIP-relative global an exported
function touches, read at the same instruction in both builds. vtables: RTTI name read back in NEW."""
import random, sys
from cd_port import Image, port_function, port_global, port_vtable, rtti_name, masked
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

old, new = Image(sys.argv[1]), Image(sys.argv[2])
def exports(im):
    return {e.name: e.address for e in im.pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name} if hasattr(im.pe, "DIRECTORY_ENTRY_EXPORT") else {}
eo, en = exports(old), exports(new)
common = sorted(set(eo) & set(en)); random.seed(1); random.shuffle(common)
in_code = lambda im, r: any(a <= r < b for a, b in im.code)
fn = [n for n in common if in_code(old, eo[n]) and in_code(new, en[n])][:40]

ok = bad = miss = 0
for n in fn:
    got, how = port_function(old, new, eo[n])
    if got is None: miss += 1
    elif got == en[n]: ok += 1
    else: bad += 1; print("WRONG fn", n, hex(got), hex(en[n]), how)
print(f"functions: {ok} right, {bad} WRONG, {miss} not found (of {len(fn)})")

def first_global(im, rva):
    for i in im.cs.disasm(im.img[rva:rva + 96], im.base + rva):
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = i.address + i.size + op.mem.disp - im.base
                if not in_code(im, t): return i.address - im.base - rva, t
    return None, None
ok = bad = miss = n_g = 0
for n in fn:
    off_o, g_old = first_global(old, eo[n]); off_n, g_new = first_global(new, en[n])
    if g_old is None or g_new is None or off_o != off_n: continue
    n_g += 1
    got, how = port_global(old, new, g_old)
    if got is None: miss += 1
    elif got == g_new: ok += 1
    else: bad += 1; print("WRONG global via", n, hex(got), hex(g_new), how)
print(f"globals: {ok} right, {bad} WRONG, {miss} not found (of {n_g})")

# vtables: walk COLs in OLD's data, port a sample, check the name in NEW.
import re, struct
data = bytes(old.img); vts = []
for m in re.finditer(re.escape(struct.pack("<I", 1)), data):
    col = m.start()
    if col % 4 or col + 24 > len(data) or old.u32(col + 20) != col: continue
    ref = data.find(struct.pack("<Q", old.base + col))
    if ref > 0: vts.append(ref + 8)
    if len(vts) >= 25: break
ok = bad = miss = 0
for vt in vts:
    name, _ = rtti_name(old, vt)
    got, how = port_vtable(old, new, vt)
    if got is None: miss += 1
    elif rtti_name(new, got)[0] == name: ok += 1
    else: bad += 1; print("WRONG vt", name, hex(got))
print(f"vtables: {ok} right, {bad} WRONG, {miss} not found/ambiguous (of {len(vts)})")
