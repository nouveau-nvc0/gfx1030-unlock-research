#!/usr/bin/env python3
"""Offline SYS record-copy path; positions are firmware file offsets."""
import hashlib, json, lzma, pathlib, struct
import capstone
E = pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b = lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha = hashlib.sha256(b).hexdigest()
assert sha == '67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
def decode(a, z, mode=capstone.CS_MODE_THUMB):
    c = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    rows = [dict(offset=hex(i.address), bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str) for i in c.disasm(b[a:z], a)]
    assert sum(len(bytes.fromhex(r['bytes'])) for r in rows) == z-a
    return rows
windows = {hex(a): decode(a,z,m) for a,z,m in [
    (0x14070,0x14178,16),(0xa5c8,0xa5f2,16),(0x1acac,0x1acf4,16),
    (0x7734,0x77e4,16),(0x1990,0x1a18,0),(0x1a1c,0x1a80,0),
    (0x14190,0x141cc,16),(0x14018,0x14062,16)]}
d = {int(r['offset'],0):r for rows in windows.values() for r in rows}
for a,m,o in [(0x1407a,'bl','0xa5c8'),(0x140a2,'cmp.w','r8, #0x18'),
 (0x14174,'b.w','0x1acac'),(0x1acd2,'bl','0x7734'),(0x1ace0,'blx','0x1990'),
 (0x77c4,'svc','#0x6b'),(0x77d4,'svc','#0x6d'),(0x77e0,'str','r2, [r1]')]:
    assert (d[a]['mnemonic'],d[a]['operands']) == (m,o), (hex(a),d[a])
pools = {hex(a):hex(struct.unpack_from('<I',b,a)[0]) for a in [0xa5f4,0x14178,0x1417c,0x14180,0x14188,0x1418c,0x1acf4,0x141cc]}
assert pools['0x1acf4'] == pools['0x14180'] == '0xe5cc24'
assert pools['0x1418c'] == '0xfff00000'
result = dict(firmware_sha256=sha, capstone_version=capstone.__version__, windows=windows, literal_pools=pools,
 definitions={'G':'uint64[e1fbe8]','H':'uint64[e1fbf0]','O':'uint32[e1fbdc]',
 'F':'uint32[e1fbc8+0c]','S':'(((F >> 1) & 31) + 1 + (F & 1)) * 0x100000',
 'record':'28 bytes at e5cc24','destination':'(H + O + S - 0x100000) modulo 2^64'},
 findings=[
 '14070 always obtains S through a5c8(0x0d). Operation0x18 branches directly to14156; it changes no record fields before tail-call1acac.',
 'Operation0x13 requires arg1=ffff, zeros28 bytes, sets DWORD0=1, sets uint64+0c=G+O and uint64+14=G+O+S. DWORD+4/+8 initially0.',
 'Operation0x0d ORs a selected bit into DWORD+4; operation0x3a does the same to DWORD+8. arg1=ffff selectsbit0, otherwise ARM register-shift result1<<(arg1+1). These are record fields, not established CC masks.',
 '1acac passes address and length1c to7734; successful result loads returned pointer and copies1c bytes frome5cc24 via ARM1990. The copy routine retains byte values; no CC arithmetic in this path.',
 '7734 constructs a page-aligned descriptor. This invocation selectsSVC6b, thenSVC6d; returned pointer plus original page offset is stored in caller output. Full physical mapping semantics not resolved here.',
 'After copying,1acac conditionally callsSVC6c using allocated byte identifier; returns prior operation status.',
 'Operation0x13 additionally calls14190 withG+O+S-1MiB; it writes high/low address words via14018 to1e130 with intervening commands1/2 at1e058. This is distinct from operation0x18 used by17210.'
 ],
 limits=[
 'Actual H/O/F and their producer ordering remain unproved. Do not assert the28-byte destination cannot overlap snapshot fields until address relations are established.',
 'No changed CC producer found. Record+4/+8 names and downstream consumer are unresolved.',
 'SVC mapping completion, runtime invocation and hardware CC acceptance are not established by this static audit. No hardware access performed.'
 ])
(E/'sys-rlc-record-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'instructions':len(d),'record_bytes':28,'operation_18':'copy record without local field changes','destination':result['definitions']['destination']}))
