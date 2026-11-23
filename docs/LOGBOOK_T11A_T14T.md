# Logbook: T11A – T14T (Phase 13 WebKit FontFace exploit chain)

Probe series for forgeRead → PTR_CHAIN → module enumeration → rr() channel → code execution.
Probe file: `probes/phase13_webkit/walk0.html` (editing IS deployment via serve.py on :443).

## Primitives established before this series

- **FontFace UAF** via CSS @font-face spray (one per reboot)
- **forgeRead via face.style**: forge CSSFontFace so `faces[zi].style` returns arbitrary memory as 8-bit Latin-1. h0[0x08] chain → h0[0x70]/h0[0x90]/h0[0x30] → target. No crash on unmapped (returns null).
- **readBytes/readQ**: 48-bit read primitive. ONLY safe with n=8 (readQ). readBytes(addr,4) corrupts the forge (h0[0x70] overwrite → OOM).
- **DELTA = 0x1710B78 FIXED**: .data.rel.ro vtable addr → first .text slot value. Confirmed 19 boots.
- **VT low-12 = 0xB28** (19 boots). ASLR is on; binary shifts as a unit.

## Boot log

### Boot 262 — T14R v1 (2026-11-20)
- VT = 0x80D025B28
- Probed low VA: readQ(0x200000) → OOM. Low VA IS MAPPED with .text-like bytes.
- ELF base hunt Phase 1 attempted but hit .text immediately.

### Boot 263 — T14R v2
- VT = 0x83E45DB28
- Full 1220-entry scan of VT+0x101F00 to VT+0x104520 (user clicked "Wait" on watchdog).
- .got non-PLT region mapped: ~100 real GOT entries, Unicode quote table, enum tables, 3 ext-lib ptrs at entries 962/967/1207.
- **Weight setter OK** (`faces[zi].weight='normal'` completed), delayed crash ~3.6s later.
- Cross-correlation: 21/21 WebKit entries shift by vtS.
- Ext-lib baseline: 962=0x80A44A830, 967=0x80A5E0D30, 1207=0x80A5C05F0.

### Boot 264 — T14R v4
- VT = 0x822491B28
- Stride-24 sample of .got non-PLT. Cross-correlation: 21/21 WebKit (3rd confirmation).
- GNP-WK=21, GNP-EX=0.

### Boot 265 — T14S v1
- VT = 0x81ED49B28
- Ext-lib entries 962/967/1207 read. Delta from boot 263: **+0x19048000** (independent ASLR).
- **Weight setter OOM** (ASLR-dependent crash on plain construction).

### Boot 266 — T14S v2
- VT = 0x839605B28
- **h0 hex dump after 24 readQ calls**: getter writes to 7 bytes of h0.
  - 0x00: 02→05 (status normalized), 0x30: 04→08, 0x40: 04→00, 0x41: 00→0C
  - 0x44: 7A→00, 0x46: 71→7A, 0x94: 48→C8 (bit 7 set)
- Ext-lib delta: +0x1B730000.

### Boot 267 — T14S v3
- VT = 0x80E1F9B28
- **Family setter OOM** (first family test on our bench — ASLR-dependent crash).
- Ext-lib delta: +0x2EA84000.

### Boot 268 — T14T v1
- VT = 0x825C35B28
- rr() calibration attempted: setR(self+0x38) and setR(self+0xA8).
- **Both returned (0x110000, 0x0)** — forge setup had overwritten h0[0x38] with a pointer.
- Root cause: wr48(h0,0x38,self+0xA8) at forge line 150 destroyed the BEEF/CAFE data.

### Boot 269 — T14T v2
- VT = 0x80E3F9B28
- rr() calibration with zero-padded patterns at h0[0xB0–0xBF].
- RR-A=(0x0, 0x10FFFF), RR-B=(0x110000, 0x0), RR-C=(0x0, 0x10FFFF).
- **All wrong** — manual byte writes (`h0[0xB2]=0xEF`) produced le32 0xBEEF0000, not 0xBEEF.
- Ext-lib delta: +0x8040000. Family setter OOM again.

### Boot 270 — T14T v3
- VT = 0x81B271B28
- rr() calibration with put32 (correct le32 encoding).
- RR-A=(0x110000, 0x0) — bisect skipped the narrow [0xBEEF, 0xCAFE] band.
- **RR-B=(0x110000, 0x5678)** — rrHi=0x5678 CORRECT, rrLo missed (bisect skip).
- RR-C=(0x110000, 0x0) — sentinel ✓.
- Diagnosis: binary search over non-monotonic function (true only in [start,end] band) fails when no halving step lands inside the band.
- Ext-lib delta: +0x3536C000. Family setter OOM.

### Boot 271 — T14T v4 ★★★
- VT = 0x824601B28, DELTA = 0x1710B78, VTS = +0x387C000
- **rr() CHANNEL FULLY CALIBRATED**:
  - RR-MAP: 0=F, BEEE=F, **BEEF=T**, C000=T, **CAFE=T**, CAFF=F, 10FFFF=F → exact [0xBEEF, 0xCAFE] ✓
  - RR-MAP2: 0=F, 1233=F, **1234=T**, 3000=T, **5678=T**, 5679=F, 10FFFF=F → exact [0x1234, 0x5678] ✓
  - **RR-FTB=0x1234, 0x5678** — find-then-bisect recovers BOTH bounds correctly.
- Engine reads **le32 at +0 (start) and le32 at +4 (end)** from h0[0x20] pointer. Continuous range. No +2 header on our bench.
- **FSET=OK** — family setter SURVIVED for the first time on our bench! Delayed crash ~2.3s later (BOOT+DOUBLE).
- Ext-lib delta: +0x341C0000.

## Venue laws established

1. **DELTA invariant**: VT slot[0] − VT = 0x1710B78 (n=19 boots).
2. **VT low-12 = 0xB28** (n=19).
3. **GOT cross-correlation**: entries 0–31 shift by vtS (21/21, n=5 boots).
4. **Ext-lib independent ASLR**: entries 962/967/1207 share one delta, different from vtS (n=7 boots).
5. **CSS getters write 7 bytes** of h0 (boot 266 dump).
6. **.text reads = uncatchable OOM** (boots 259, 260, 262 + earlier).
7. **readQ safe on unmapped** (returns null).
8. **Setter property gating**: style THROWS (both benches), family+weight do NOT throw. Construction irrelevant (KWEG-OK).
9. **Setter writes invisible in reclaimed backer** (cobrajet302gt D-null, boot 271 comment).
10. **rr() channel**: setR(addr) + chk(codepoint) reads le32 pair at addr as [start, end] range. find-then-bisect recovers both bounds. ~50 chk calls per read.
11. **Family setter survives on some ASLR slides** (boot 271 FSET=OK, boots 267/269/270 OOM).

## Address space map

```
Low VA:           0x200000 is MAPPED .text (OOM proven boot 262)
G47 target:       0x39875f0 (FIXED, non-ASLR'd)
Code band:        0x800000000–0x900000000 (per-library ASLR, INTERLEAVED)

WebKit binary (relative to VT):
  .text:          VT-46.3MB to VT-4MB
  .rodata:        VT-0x400000 to VT-0x140000 (readable ASCII)
  .data.rel.ro:   ~VT-0x130000 to VT+0x100000 (vtables)
  vtable arrays:  VT+0x100000 to VT+0x101F00
  .got (real):    VT+0x101F00 to ~VT+0x102200 (~100 entries)
  data tables:    ~VT+0x102200 to ~VT+0x104520 (Unicode quotes, enums, 3 ext-lib ptrs)
  .got.plt:       VT+0x104520 to VT+0x104F00+ (316 entries, 9 libraries)
  .dynamic:       STRIPPED BY SONY
  .bss:           VT+0x106DC0+
```

## Ext-lib ASLR deltas (from boot 263 baseline)

| Boot | VT | Ext-lib delta |
|------|-----|--------------|
| 263 | 0x83E45DB28 | (baseline) |
| 265 | 0x81ED49B28 | +0x19048000 |
| 266 | 0x839605B28 | +0x1B730000 |
| 267 | 0x80E1F9B28 | +0x2EA84000 |
| 269 | 0x80E3F9B28 | +0x8040000 |
| 270 | 0x81B271B28 | +0x3536C000 |
| 271 | 0x824601B28 | +0x341C0000 |

## Next steps

1. **Use rr() to read .text** — the channel is calibrated. Each read = ~50 chk calls, no OOM risk. Can read ELF headers, program headers, .text function prologues.
2. **ELF base hunt via rr()** — scan downward from VT for the ELF magic (0x7F454C46 as two le32 reads).
3. **Family setter h0 diff** — boot 271 FSET=OK means the setter completed. Need to snapshot h0 before/after to find the write target.
4. **Push T9G–T14T to fork** (last push was T9F as 6b6e04b2).
