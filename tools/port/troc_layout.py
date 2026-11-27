"""troc_layout.py BUILD EXE RTTI.json NAMES OUT.json

Message layouts straight from the game: runs each pa::TrocTr<NAME> parser
(vtable slot 2) in an emulator (unicorn) on a fake payload and records every
field it reads as cursor:size. A new patch that changes a message shows up as
a different size or field list; compare two builds' OUT.json with --diff.

  py -3.12 -I troc_layout.py 3840 C:/tmp/cd_exe/latest/CrimsonDesert.exe rtti_3840.json MoveActorReq,StartActionReq out.json
  py -3.12 -I troc_layout.py --diff old.json new.json

RTTI.json: tools/scripts/rtti_dump.py. NAMES without the pa::TrocTr prefix.
BUILD picks the stubs below. For a NEW build add an entry:
  read  = (RVA of the stream's default Read(stream, dst, n), cursor offset in
          the stream). In MoveActorReq's slot-2 function the first field read
          is "lea rax,[rip+X]; mov r8d,4; ...; cmp r9, rax; ...; call X": X is
          the Read. The cursor is the u32 after the stream's buffer pointer and
          length (stream+0x2C in 3840, +0x1C in 2976).
  alloc = the game allocator's entries (malloc with size in rdx or rcx, free):
          the emulation stops "UNMAPPED" inside them; stub each one.
Validated: 2976 MoveActorReq/Ack = 514/235 and StartAction 725, the sizes
captured live on that build.
"""
import json, sys, struct, pefile, capstone, collections
from capstone import x86 as cx
from unicorn import *
from unicorn.x86_const import *
import unicorn.x86_const as K
CFG = {
 '2976': dict(read=(0x141F270, 0x1C), alloc={0x47EFDB8: 'rdx', 0x47F02BC: 'rdx', 0x47EF9B0: 'rcx'}),
 '3840': dict(read=(0x16CE340, 0x2C),
              alloc={0x4CF184C: 'rdx', 0x4CF1840: 'rdx', 0x4CF1D50: 'rdx', 0x4CF14EC: 'rcx', 0x4CF15B4: 'rcx'}),
}
if sys.argv[1] == '--diff':
    a, b = json.load(open(sys.argv[2])), json.load(open(sys.argv[3]))
    for n in a:
        if not a.get(n) or not b.get(n): continue
        fa, fb = a[n]['z'], b[n]['z']
        la = [f'{c:X}:{z}' for c, z in fa['fields']]; lb = [f'{c:X}:{z}' for c, z in fb['fields']]
        if la != lb or fa['max'] != fb['max']:
            print(f"== {n}: {fa['max']} -> {fb['max']} bytes")
            if len(la) < 300: print('  old', ' '.join(la)); print('  new', ' '.join(lb))
    sys.exit(0)
cfg = dict(CFG[sys.argv[1]], exe=sys.argv[2], rtti=sys.argv[3]); names = sys.argv[4].split(','); outp = sys.argv[5]
pe = pefile.PE(cfg['exe'], fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
base = pe.OPTIONAL_HEADER.ImageBase
imgb = bytearray(pe.get_memory_mapped_image()); imgb += bytes(max(0, pe.OPTIONAL_HEADER.SizeOfImage - len(imgb)))
FAKE = 0x50000000; IMP = {}
for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
    for imp in e.imports:
        k = len(IMP); IMP[FAKE + 16 * k] = (imp.name or b'ord').decode()
        struct.pack_into('<Q', imgb, imp.address - base, FAKE + 16 * k)
img = bytes(imgb)
print(len(IMP), 'imports stubbed', flush=True)
c = json.load(open(cfg['rtti']))['classes']; c = list(c.values()) if isinstance(c, dict) else c
vts = {x['name']: int(x['vtables'][0]['rva'], 16) for x in c if x['name'].startswith('pa::TrocTr')}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
REGS = {getattr(cx, n): getattr(K, 'UC_X86_REG_' + n[8:]) for n in dir(cx) if n.startswith('X86_REG_') and hasattr(K, 'UC_X86_REG_' + n[8:])}
STK, THIS, OUT, HOLD, PKT, TEB, TLS, HEAP, RET = 0x7000000, 0x10000000, 0x10100000, 0x10200000, 0x20000000, 0x30000000, 0x31000000, 0x40000000, 0x11000000
def run(name, N, fill):
    f = struct.unpack_from('<Q', img, vts[name] + 16)[0]
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(base, (len(img) + 0xFFF) & ~0xFFF); mu.mem_write(base, img)
    for a, s in ((STK, 0x200000), (THIS, 0x10000), (OUT, 0x1000), (HOLD, 0x1000), (PKT, 0x20000), (TEB, 0x1000), (TLS, 0x100000), (HEAP, 0x4000000), (RET, 0x1000)):
        mu.mem_map(a, s)
    mu.mem_write(RET, b'\xF4')
    mu.mem_map(FAKE, 0x100000); mu.mem_write(FAKE, b'\xC3' * 0x100000)
    def on_imp(uc, addr, sz, ud):
        nm = IMP.get(addr, '?'); a1, a2, a3 = uc.reg_read(UC_X86_REG_RCX), uc.reg_read(UC_X86_REG_RDX), uc.reg_read(UC_X86_REG_R8)
        rax = 0
        try:
            if nm == 'memset': uc.mem_write(a1, bytes([a2 & 0xFF]) * a3); rax = a1
            elif nm in ('memcpy', 'memmove'):
                if a3:
                    uc.mem_write(a1, bytes(uc.mem_read(a2, a3)))
                    o = a2 - PKT - 5
                    if 0 <= o < N + 64: reads.append(o + a3)
                rax = a1
            elif nm == 'memcmp':
                x, y = bytes(uc.mem_read(a1, a3)), bytes(uc.mem_read(a2, a3)); rax = ((x > y) - (x < y)) & 0xFFFFFFFF
            else: imps.append(nm)
        except UcError: imps.append('FAULT ' + nm)
        uc.reg_write(UC_X86_REG_RAX, rax)
    mu.hook_add(UC_HOOK_CODE, on_imp, begin=FAKE, end=FAKE + 0x100000)
    imps = []
    pkt = bytearray([fill]) * (N + 5); pkt[0:5] = bytes(5); struct.pack_into('<H', pkt, 3, N); mu.mem_write(PKT, bytes(pkt))
    hold = bytearray(0x100); struct.pack_into('<H', hold, 0x10, N + 5); struct.pack_into('<Q', hold, 0x18, PKT); mu.mem_write(HOLD, bytes(hold))
    mu.mem_write(TEB + 0x30, struct.pack('<Q', TEB)); mu.mem_write(TEB + 0x58, struct.pack('<Q', TLS))
    for i in range(64): mu.mem_write(TLS + 8 * i, struct.pack('<Q', TLS + 0x1000 + 0x1000 * i))
    mu.reg_write(UC_X86_REG_GS_BASE, TEB)
    sp = STK + 0x100000 - 8; mu.mem_write(sp, struct.pack('<Q', RET))
    mu.reg_write(UC_X86_REG_RSP, sp); mu.reg_write(UC_X86_REG_RCX, THIS); mu.reg_write(UC_X86_REG_RDX, OUT); mu.reg_write(UC_X86_REG_R8, HOLD)
    reads, fields, heap, lazy = [], [], [HEAP], [0]
    def rv(r): return 0 if r == 0 else mu.reg_read(REGS[r])
    def on_read(uc, acc, addr, sz, val, ud):
        o = addr - PKT - 5
        if 0 <= o < N + 64: reads.append(o + sz)
    mu.hook_add(UC_HOOK_MEM_READ, on_read, begin=PKT, end=PKT + 0x20000)
    RA, CUR = cfg['read']
    def on_rd(uc, addr, sz, ud):
        rcx = uc.reg_read(UC_X86_REG_RCX); n = uc.reg_read(UC_X86_REG_R8) & 0xFFFFFFFF
        try: cur = struct.unpack('<I', uc.mem_read(rcx + CUR, 4))[0]
        except UcError: cur = -1
        fields.append((cur, n))
    mu.hook_add(UC_HOOK_CODE, on_rd, begin=base + RA, end=base + RA)
    def on_alloc(uc, addr, sz, ud):
        r = addr - base; reg = cfg['alloc'][r]
        n = uc.reg_read(UC_X86_REG_RCX if reg == 'rcx' else UC_X86_REG_RDX); n = n if 0 < n < 0x100000 else 0x1000
        p = heap[0]; heap[0] += (n + 0x3F) & ~0xF
        uc.reg_write(UC_X86_REG_RAX, p)
        rsp = uc.reg_read(UC_X86_REG_RSP); uc.reg_write(UC_X86_REG_RIP, struct.unpack('<Q', uc.mem_read(rsp, 8))[0]); uc.reg_write(UC_X86_REG_RSP, rsp + 8)
    for a in cfg['alloc']: mu.hook_add(UC_HOOK_CODE, on_alloc, begin=base + a, end=base + a)
    def on_unm(uc, acc, addr, sz, val, ud):
        if lazy[0] > 64 or addr < 0x10000 and False: return False
        try: uc.mem_map(addr & ~0xFFF, 0x2000)
        except UcError: return False
        lazy[0] += 1; return True
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, on_unm)
    blocks = collections.deque(maxlen=12)
    mu.hook_add(UC_HOOK_BLOCK, lambda uc, a, sz, ud: blocks.append(a))
    err, start, skipped = None, f, 0
    while True:
        try: mu.emu_start(start, RET, count=2_000_000); break
        except UcError as e:
            rip = mu.reg_read(UC_X86_REG_RIP)
            if e.errno != UC_ERR_INSN_INVALID or skipped > 100000: err = str(e); break
            try: ins = next(md.disasm(bytes(mu.mem_read(rip, 15)), rip))
            except Exception: err = 'decode'; break
            if not ins.mnemonic.startswith('v'): err = 'insn ' + ins.mnemonic; break
            for i, op in enumerate(ins.operands):
                if op.type == cx.X86_OP_MEM:
                    m = op.mem
                    a = ((rip + ins.size if m.base == cx.X86_REG_RIP else rv(m.base)) + rv(m.index) * m.scale + m.disp) & ((1 << 64) - 1)
                    if i == 0 and len(ins.operands) >= 2:
                        try: mu.mem_write(a, bytes(op.size))
                        except UcError: pass
                    else:
                        o = a - PKT - 5
                        if 0 <= o < N + 64: reads.append(o + op.size)
            skipped += 1; start = rip + ins.size
    done = mu.reg_read(UC_X86_REG_RIP) == RET
    if not done: err = f"{err} at {mu.reg_read(UC_X86_REG_RIP):#x} after " + ' '.join(f'{b - base:X}' if b > base else f'{b:#x}' for b in blocks)
    return dict(imps=sorted(set(imps)), max=max(reads, default=0), fields=fields, done=done, err=err, lazy=lazy[0])
res = {}
for n in names:
    full = 'pa::TrocTr' + n
    if full not in vts: res[n] = None; print(n, 'NO CLASS'); continue
    a = run(full, 6000, 0); b = run(full, 6000, 1)
    res[n] = dict(z=a, o=b)
    print(f"{n:42} zero:{a['max']:5} {'ok ' if a['done'] else 'ERR'} one:{b['max']:5} {'ok ' if b['done'] else 'ERR'} nfields {len(a['fields'])} {a['err'] or ''}", flush=True)
json.dump(res, open(outp, 'w'))
