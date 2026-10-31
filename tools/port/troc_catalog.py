"""troc_catalog.py EXE RTTI.json OUT.csv -> name,opcode,kind,instance,min,max

In the file every static Troc instance carries the BASE pa::Troc vtable plus its
opcode; a 67-byte dynamic initializer per message then does
  lea r, [rip+derived_vtable] ; mov [rip+instance], r
so instance -> class name comes from those lea/mov pairs.
"""
import json, re, struct, sys, pefile
import numpy as np
pe = pefile.PE(sys.argv[1], fast_load=True)
img = pe.get_memory_mapped_image()
base = pe.OPTIONAL_HEADER.ImageBase
d = json.load(open(sys.argv[2]))
classes = d["classes"].values() if isinstance(d["classes"], dict) else d["classes"]
vt2name, troc_vt = {}, None
for c in classes:
    for v in c["vtables"]:
        if c["name"] == "pa::Troc": troc_vt = int(v["rva"], 16)
        elif c["name"].startswith("pa::TrocTr"): vt2name[int(v["rva"], 16)] = c["name"][4:]
q = np.frombuffer(img[: len(img) // 8 * 8], dtype="<u8")
inst = {int(i) * 8 for i in np.nonzero(q == base + troc_vt)[0]}
print(f"pa::Troc vtable 0x{troc_vt:X}, {len(inst)} instances in file, {len(vt2name)} TrocTr classes")
pair = re.compile(rb"([\x48\x4C])\x8D([\x05\x0D\x15\x1D\x25\x2D\x35\x3D])(.{4})([\x48\x4C])\x89([\x05\x0D\x15\x1D\x25\x2D\x35\x3D])(.{4})", re.DOTALL)
inst2name = {}
for m in pair.finditer(img):
    if m.group(1) != m.group(4) or m.group(2) != m.group(5): continue
    s = m.start()
    vt = s + 7 + struct.unpack("<i", m.group(3))[0]
    dst = s + 14 + struct.unpack("<i", m.group(6))[0]
    if vt in vt2name and dst in inst:
        inst2name.setdefault(dst, set()).add(vt2name[vt])
rows = []
for r in sorted(inst):
    kind, op = struct.unpack_from("<II", img, r + 8)
    mn, mx = struct.unpack_from("<HH", img, r + 0x18)
    names = inst2name.get(r, {"?"})
    rows.append((",".join(sorted(names)), op, kind, r, mn, mx))
with open(sys.argv[3], "w") as f:
    f.write("name,opcode,kind,instance,min,max\n")
    for n, op, kind, r, mn, mx in sorted(rows):
        f.write(f"{n},{op},{kind:#x},{r:#x},{mn},{mx}\n")
named = [x for x in rows if x[0] != "?" and "," not in x[0]]
print(f"named {len(named)}  unnamed {sum(x[0]=='?' for x in rows)}  ambiguous {sum(',' in x[0] for x in rows)}")
print(f"instance range 0x{min(inst):X}..0x{max(inst)+0x90:X}")
