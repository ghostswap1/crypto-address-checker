// Address encodings: Base58 (any alphabet), Base58Check, Monero's block Base58,
// Bech32/Bech32m, CashAddr, RFC 4648 Base32 and Base64.

import { sha256d } from "./hash.js";

export const BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

export function base58Decode(str, alphabet = BTC_ALPHABET) {
  if (!str) return null;
  const bytes = [];
  for (const ch of str) {
    let carry = alphabet.indexOf(ch);
    if (carry < 0) return null;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const ch of str) {
    if (ch !== alphabet[0]) break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

/** Returns the payload (without the 4-byte checksum), or null on a bad checksum. */
export function base58CheckDecode(str, alphabet = BTC_ALPHABET) {
  const raw = base58Decode(str, alphabet);
  if (!raw || raw.length < 5) return null;
  const payload = raw.slice(0, -4);
  const sum = sha256d(payload);
  for (let i = 0; i < 4; i++) if (sum[i] !== raw[raw.length - 4 + i]) return null;
  return payload;
}

// Monero splits Base58 into 8-byte blocks that each encode to 11 characters.
const XMR_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11];

export function moneroBase58Decode(str) {
  const out = [];
  for (let i = 0; i < str.length; i += 11) {
    const chunk = str.slice(i, i + 11);
    const size = XMR_BLOCK_SIZES.indexOf(chunk.length);
    if (size < 0) return null;
    let num = 0n;
    for (const ch of chunk) {
      const v = BTC_ALPHABET.indexOf(ch);
      if (v < 0) return null;
      num = num * 58n + BigInt(v);
    }
    if (num >> BigInt(size * 8) !== 0n) return null;
    const block = new Array(size);
    for (let j = size - 1; j >= 0; j--) {
      block[j] = Number(num & 0xffn);
      num >>= 8n;
    }
    out.push(...block);
  }
  return Uint8Array.from(out);
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

/**
 * Decodes Bech32 or Bech32m. Returns { hrp, data (5-bit words), variant } or null.
 * `limit` is the maximum string length (90 in BIP173; Zcash unified and Cardano
 * addresses are longer, so callers pass Infinity for those).
 */
export function bech32Decode(str, limit = 90) {
  if (str.length > limit) return null;
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) return null;
  const s = str.toLowerCase();
  const pos = s.lastIndexOf("1");
  if (pos < 1 || pos + 7 > s.length) return null;
  const hrp = s.slice(0, pos);
  for (const ch of hrp) if (ch.charCodeAt(0) < 33 || ch.charCodeAt(0) > 126) return null;
  const data = [];
  for (const ch of s.slice(pos + 1)) {
    const v = BECH32_CHARSET.indexOf(ch);
    if (v < 0) return null;
    data.push(v);
  }
  const expanded = [];
  for (const ch of hrp) expanded.push(ch.charCodeAt(0) >> 5);
  expanded.push(0);
  for (const ch of hrp) expanded.push(ch.charCodeAt(0) & 31);
  const mod = bech32Polymod([...expanded, ...data]);
  const variant = mod === BECH32_CONST ? "bech32" : mod === BECH32M_CONST ? "bech32m" : null;
  if (!variant) return null;
  return { hrp, data: data.slice(0, -6), variant };
}

/** Regroups bits (5-bit words to bytes and back). Returns null on invalid padding. */
export function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) return null;
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
    acc &= (1 << bits) - 1;
  }
  if (pad) {
    if (bits) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null;
  }
  return Uint8Array.from(out);
}

/** Decodes a SegWit address for the given human-readable part (bc, ltc, tb…). */
export function segwitDecode(hrp, str) {
  const dec = bech32Decode(str);
  if (!dec || dec.hrp !== hrp || dec.data.length < 1) return null;
  const version = dec.data[0];
  if (version > 16) return null;
  const program = convertBits(dec.data.slice(1), 5, 8, false);
  if (!program || program.length < 2 || program.length > 40) return null;
  if (version === 0 && program.length !== 20 && program.length !== 32) return null;
  if ((version === 0) !== (dec.variant === "bech32")) return null;
  return { version, program };
}

function cashaddrPolymod(values) {
  const GEN = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= GEN[i];
  }
  return c ^ 1n;
}

/** Decodes a Bitcoin Cash CashAddr. Returns { type: 'p2pkh'|'p2sh', hash } or null. */
export function cashaddrDecode(str, prefix = "bitcoincash") {
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) return null;
  let s = str.toLowerCase();
  if (!s.includes(":")) s = `${prefix}:${s}`;
  const [pre, payload] = s.split(":");
  if (pre !== prefix || !payload) return null;
  const data = [];
  for (const ch of payload) {
    const v = BECH32_CHARSET.indexOf(ch);
    if (v < 0) return null;
    data.push(v);
  }
  const values = [...[...pre].map((ch) => ch.charCodeAt(0) & 31), 0, ...data];
  if (cashaddrPolymod(values) !== 0n) return null;
  const bytes = convertBits(data.slice(0, -8), 5, 8, false);
  if (!bytes || bytes.length < 21) return null;
  const versionByte = bytes[0];
  const sizes = [20, 24, 28, 32, 40, 48, 56, 64];
  const hash = bytes.slice(1);
  if (hash.length !== sizes[versionByte & 7]) return null;
  const typeBits = versionByte >> 3;
  if (typeBits > 1) return null;
  return { type: typeBits === 0 ? "p2pkh" : "p2sh", hash };
}

export function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const out = [];
  let bits = 0;
  let acc = 0;
  for (const ch of str) {
    const v = alphabet.indexOf(ch);
    if (v < 0) return null;
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

export function base64Decode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const out = [];
  let bits = 0;
  let acc = 0;
  for (const ch of s.replace(/=+$/, "")) {
    acc = (acc << 6) | alphabet.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}
