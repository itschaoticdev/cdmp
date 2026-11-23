"""Resolve the offsets cd_port.py could not: vf-of-RTTI-class functions, the
opcode-tagged server writers, and the Troc instance range. Usage:
  resolve_manual.py OLD.exe NEW.exe rtti_old.json rtti_new.json troc_new.csv"""
import sys, json, struct, csv, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

class Img:
    def __init__(s, p):
        s.pe = pefile.PE(p, fast_load=True); s.data = open(p, 'rb').read(); s.base = s.pe.OPTIONAL_HEADER.ImageBase
    def off(s, rva): return s.pe.get_offset_from_rva(rva)
    def q(s, rva): return struct.unpack('<Q', s.data[s.off(rva):s.off(rva) + 8])[0]
    def bytes(s, rva, n): o = s.off(rva); return s.data[o:o + n]
    def vf(s, vt, i): return s.q(vt + 8 * i) - s.base
    def code(s, rva, n=0x400):
        md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = False
        return list(md.disasm(s.bytes(rva, n), s.base + rva))

def vt_index(rtti):
    m = {}
    for mangled, c in rtti['classes'].items():
        for v in c['vtables']: m[int(v['rva'], 16)] = (mangled, v['offset'])
    return m
def vt_by_name(rtti):
    m = {}
    for mangled, c in rtti['classes'].items():
        for v in c['vtables']: m[(mangled, v['offset'])] = (int(v['rva'], 16), v['length'])
    return m

old, new = Img(sys.argv[1]), Img(sys.argv[2])
ro, rn = json.load(open(sys.argv[3])), json.load(open(sys.argv[4]))
oi, nn = vt_index(ro), vt_by_name(rn)
oname = vt_by_name(ro)

def find_vf_owner(img, idx, target, maxvf=64):
    """Classes in OLD whose vtable slot holds target."""
    out = []
    for (mangled, off), (vt, ln) in idx.items():
        for i in range(min(ln, maxvf)):
            try:
                if img.vf(vt, i) == target: out.append((mangled, off, i))
            except Exception: break
    return out

res = {}
for name, rva in [('kPointClimbEnter', 0x75FFC0), ('kRideOnEnter', 0x74F270), ('kRideOffEnter', 0x750240)]:
    owners = find_vf_owner(old, oname, rva)
    cands = set()
    for mangled, off, i in owners:
        if (mangled, off) in nn: cands.add(new.vf(nn[(mangled, off)][0], i))
    res[name] = (sorted(cands), owners[:4])
    print(name, [hex(c) for c in cands], owners[:4])

# Docking writer: the call at +0x10D in ServerFrameEventChangeDockingSocket vf1 (old) -> same class new
def calls(img, fn, n=0x600):
    return [(i.address - img.base - fn, int(i.op_str, 16) - img.base) for i in img.code(fn, n)
            if i.mnemonic == 'call' and i.op_str.startswith('0x')]
for mangled, c in rn['classes'].items():
    if 'ServerFrameEventChangeDockingSocket' in mangled:
        for v in c['vtables']:
            vt = int(v['rva'], 16); f1 = new.vf(vt, 1)
            print('docking', mangled, 'vf1', hex(f1), [(hex(a), hex(b)) for a, b in calls(new, f1)])
for mangled, c in ro['classes'].items():
    if 'ServerFrameEventChangeDockingSocket' in mangled:
        for v in c['vtables']:
            vt = int(v['rva'], 16); f1 = old.vf(vt, 1)
            print('docking OLD', mangled, 'vf1', hex(f1), [(hex(a), hex(b)) for a, b in calls(old, f1)])

# Other-equip writer: functions with the old Head bytes that contain imm 2426 (new id of OtherEquipItemAck)
head = old.bytes(0x2C6E5A0, 16)
print('equip head', head.hex())
text = new.pe.sections[0]; lo = text.VirtualAddress; tb = new.data[text.PointerToRawData:text.PointerToRawData + text.SizeOfRawData]
p = 0; hits = []
while True:
    p = tb.find(head[:12], p)
    if p < 0: break
    hits.append(lo + p); p += 1
print('head hits', len(hits))
for h in hits:
    ins = new.code(h, 0x300)
    imm = [i for i in ins if '0x97a' in i.op_str.lower()]
    if imm: print('  equip cand', hex(h), [(hex(i.address - new.base), i.mnemonic, i.op_str) for i in imm[:3]])
ins = old.code(0x2C6E5A0, 0x300)
print('old equip uses', [(hex(i.address - old.base - 0x2C6E5A0), i.mnemonic, i.op_str) for i in ins if '0xc40' in i.op_str.lower()][:3])
