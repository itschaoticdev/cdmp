"""cd_port.py OLD.exe NEW.exe [offsets.h] [--json out.json]

Carries the RVAs in src/mod/game/offsets.h from the build they were verified on
(OLD) to a new build (NEW), offline. Nothing here is trusted until cdmp_probe
confirms it in game; the report says how each value was found and how sure.

  functions  (k<Name> with a k<Name>Head[] next to it, or listed in FUNCS)
             the first bytes of the function, with rel32 / RIP displacements
             masked, grown until they match exactly once in NEW.
  globals    every RIP-relative reference to the global in OLD is turned into a
             masked pattern (the referencing instruction plus its neighbours);
             each pattern that is unique in NEW votes for the address its
             instruction points at there.
  vtables    by RTTI: vtable[-1] -> CompleteObjectLocator -> TypeDescriptor
             name in OLD, then the same name (and COL offset) in NEW.
  the rest   struct offsets, opcodes and constants are not addresses; they are
             listed as "verify in game" and left unchanged.
"""
import json, re, struct, sys
import numpy as np
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

FUNCS = {"kClientClock"}          # functions without a Head[] array
VTABLE_PREFIX = "kVt"
SKIP = {"kImageBase", "kPeTimestamp"}


class Image:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.pe.parse_data_directories(directories=[0])   # exports, before the mapping closes the file
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = self.pe.get_memory_mapped_image(ImageBase=self.base)
        self.ts = self.pe.FILE_HEADER.TimeDateStamp
        self.code = [(s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData))
                     for s in self.pe.sections if s.Characteristics & 0x20000000]
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64); self.cs.detail = True
        self._text = None

    def text(self):
        """(start_rva, bytes) of the code covering all executable sections."""
        if self._text is None:
            lo = min(a for a, _ in self.code); hi = max(b for _, b in self.code)
            self._text = (lo, bytes(self.img[lo:hi]))
        return self._text

    def insn_at(self, rva):
        for i in self.cs.disasm(self.img[rva:rva + 16], self.base + rva, count=1):
            return i
        return None

    def u64(self, rva): return struct.unpack_from("<Q", self.img, rva)[0]
    def u32(self, rva): return struct.unpack_from("<I", self.img, rva)[0]


def masked(img, start, length):
    """Pattern (bytes, mask) for the instructions in [start, start+length): every
    rel32 branch target and RIP displacement is a wildcard."""
    pat, msk, rva, end = bytearray(), bytearray(), start, start + length
    while rva < end:
        i = img.insn_at(rva)
        if i is None: break
        b = bytearray(i.bytes); m = bytearray(b"\xff" * len(b))
        disp_off = i.disp_offset if getattr(i, "disp_offset", 0) else 0
        if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP for op in i.operands) and disp_off:
            m[disp_off:disp_off + 4] = b"\0\0\0\0"
        imm_off, imm_size = getattr(i, "imm_offset", 0), getattr(i, "imm_size", 0)
        if i.group(1) or i.group(2) or i.group(7):   # jump, call, relative branch
            if imm_off and imm_size == 4: m[imm_off:imm_off + 4] = b"\0\0\0\0"
        pat += b; msk += m; rva += i.size
    return bytes(pat), bytes(msk)


def regex(pat, msk):
    return re.compile(b"".join(re.escape(bytes([p])) if k else b"." for p, k in zip(pat, msk)), re.DOTALL)


def find(img, pat, msk, limit=3):
    lo, text = img.text()
    return [lo + m.start() for _, m in zip(range(limit), regex(pat, msk).finditer(text))]


def port_function(old, new, rva):
    for n in (24, 40, 64, 96, 160, 256):
        pat, msk = masked(old, rva, n)
        hits = find(new, pat, msk)
        if len(hits) == 1: return hits[0], f"prologue {len(pat)} B unique"
        if not hits: return None, f"prologue {len(pat)} B not found"
    return None, f"prologue still ambiguous ({len(hits)}+ hits)"


def rip_xrefs(img, target, cap=40):
    """Instruction RVAs in code whose RIP-relative operand points at target."""
    lo, text = img.text()
    a = np.frombuffer(text, dtype=np.uint8)
    out = []
    for tail in (0, 1, 2, 4):   # bytes after disp32 (imm8/16/32)
        n = len(a) - 4 - tail
        if n <= 0: continue
        disp = (a[0:n].astype(np.int64) | (a[1:n + 1].astype(np.int64) << 8) |
                (a[2:n + 2].astype(np.int64) << 16) | (a[3:n + 3].astype(np.int64) << 24))
        disp = np.where(disp >= 2**31, disp - 2**32, disp)
        pos = np.nonzero(lo + np.arange(n) + 4 + tail + disp == target)[0]
        for p in pos[:cap * 4]:
            drva = lo + int(p)
            for back in range(1, 8):
                i = old_insn = img.insn_at(drva - back)
                if i and i.size > back and getattr(i, "disp_offset", 0) == back and \
                        any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and
                            i.address + i.size + op.mem.disp - img.base == target for op in i.operands):
                    out.append(drva - back); break
        if len(out) >= cap: break
    return sorted(set(out))[:cap]


def rip_target(img, insn_rva):
    i = img.insn_at(insn_rva)
    for op in (i.operands if i else []):
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return i.address + i.size + op.mem.disp - img.base
    return None


def port_global(old, new, rva):
    refs = rip_xrefs(old, rva)
    if not refs: return None, "no RIP references in OLD"
    votes = {}
    for r in refs:
        for before, after in ((0, 24), (12, 24), (0, 48), (24, 48)):
            start = r
            if before:   # step back whole instructions
                for b in range(before, 0, -1):
                    i = old.insn_at(r - b)
                    if i and r - b + i.size <= r and i.address - old.base + i.size == r: start = r - b; break
            pat, msk = masked(old, start, (r - start) + after)
            hits = find(new, pat, msk)
            if len(hits) == 1:
                t = rip_target(new, hits[0] + (r - start))
                if t is not None: votes[t] = votes.get(t, 0) + 1
                break
    if not votes: return None, f"{len(refs)} refs, none unique in NEW"
    best = max(votes, key=votes.get); total = sum(votes.values())
    return best, f"{votes[best]}/{total} votes from {len(refs)} refs" + ("" if votes[best] == total else f" (split: {sorted(votes.values(), reverse=True)})")


def rtti_name(img, vt):
    col = img.u64(vt - 8) - img.base
    if img.u32(col) != 1: return None, None
    td = img.u32(col + 12); off = img.u32(col + 4)
    name = bytes(img.img[td + 16: td + 16 + 512]).split(b"\0")[0]
    return name, off


def port_vtable(old, new, vt):
    name, off = rtti_name(old, vt)
    if not name: return None, "no RTTI at vtable-8 in OLD"
    data = bytes(new.img)
    for m in re.finditer(re.escape(name + b"\0"), data):
        td = m.start() - 16
        for c in re.finditer(re.escape(struct.pack("<I", td)), data):
            col = c.start() - 12
            if col < 0 or new.u32(col) != 1 or new.u32(col + 4) != off or new.u32(col + 20) != col: continue
            refs = [x.start() for x in re.finditer(re.escape(struct.pack("<Q", new.base + col)), data)]
            if len(refs) == 1: return refs[0] + 8, f"RTTI {name.decode(errors='replace')} off {off}"
            if refs: return None, f"RTTI {name.decode(errors='replace')}: {len(refs)} vtables"
    return None, f"RTTI {name.decode(errors='replace')} not in NEW"


def parse_offsets(path):
    src = open(path, encoding="utf-8").read()
    vals = dict((m.group(1), int(m.group(2), 0)) for m in
                re.finditer(r"inline constexpr \w+ (k\w+) = (0x[0-9A-Fa-f]+|\d+)", src))
    heads = set(re.findall(r"inline constexpr uint8_t (k\w+)Head\[\]", src))
    return src, vals, heads


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    old, new = Image(args[0]), Image(args[1])
    src, vals, heads = parse_offsets(args[2] if len(args) > 2 else r"C:\cdmp\src\mod\game\offsets.h")
    lo_old = min(a for a, _ in old.code); size_old = len(old.img)
    rows = []
    for k, v in vals.items():
        if k in SKIP: continue
        is_rva = 0x1000 <= v < size_old and (k in heads or k in FUNCS or k.startswith(VTABLE_PREFIX)
                                              or any(k == x for x in ("kTrocInstancesBegin", "kTrocInstancesEnd"))
                                              or (v >= 0x100000 and not k.startswith(("kOp", "kStat", "kCamera_", "kCameraBlock"))))
        if not is_rva:
            rows.append((k, v, None, "verify in game", "not an address")); continue
        if k.startswith(VTABLE_PREFIX):
            nv, how = port_vtable(old, new, v); kind = "vtable"
        elif k in heads or k in FUNCS:
            nv, how = port_function(old, new, v); kind = "function"
        else:
            nv, how = port_global(old, new, v); kind = "global"
        rows.append((k, v, nv, kind, how))
    print(f"OLD stamp 0x{old.ts:08X}  NEW stamp 0x{new.ts:08X}")
    for k, v, nv, kind, how in rows:
        nvs = "-" if nv is None else f"0x{nv:X}"
        print(f"{k:34s} 0x{v:<9X} -> {nvs:11s} {kind:14s} {how}")
    for k in sorted(heads):
        nv = next((r[2] for r in rows if r[0] == k), None)
        if nv: print(f"{k}Head new: {{{', '.join(f'0x{b:02X}' for b in new.img[nv:nv + 16])}}}")
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        json.dump([dict(name=k, old=v, new=nv, kind=kind, how=how) for k, v, nv, kind, how in rows], open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
