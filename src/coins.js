// One checker per coin. Each returns { type, network, checksum, notes? } for a
// valid address, or { error } when the address is not valid for that coin.

import { keccak256, crc16xmodem } from "./hash.js";
import {
  XRP_ALPHABET,
  base58Decode,
  base58CheckDecode,
  moneroBase58Decode,
  bech32Decode,
  convertBits,
  segwitDecode,
  cashaddrDecode,
  base32Decode,
  base64Decode,
} from "./encodings.js";

const fail = (error) => ({ error });
const ok = (type, extra = {}) => ({ type, network: "mainnet", checksum: "verified", notes: [], ...extra });

/** Bitcoin-style coins: Base58Check version bytes plus an optional SegWit prefix. */
function utxoChecker({ p2pkh, p2sh, hrp, testHrp, name }) {
  return (addr) => {
    const lower = addr.toLowerCase();
    if (hrp && lower.startsWith(`${hrp}1`)) {
      const sw = segwitDecode(hrp, addr);
      if (!sw) return fail(`Invalid ${name} SegWit address: the checksum or length is wrong.`);
      if (sw.version === 0) return ok(sw.program.length === 20 ? "SegWit (P2WPKH)" : "SegWit (P2WSH)");
      if (sw.version === 1 && sw.program.length === 32) return ok("Taproot (P2TR)");
      return ok(`SegWit v${sw.version}`, {
        notes: ["Future SegWit version. Many wallets and services cannot send to it yet."],
      });
    }
    if (testHrp && lower.startsWith(`${testHrp}1`)) {
      return segwitDecode(testHrp, addr)
        ? ok("SegWit", { network: "testnet", notes: ["This is a testnet address. Never send real coins to it."] })
        : fail(`Invalid ${name} testnet address.`);
    }
    const payload = base58CheckDecode(addr);
    if (!payload) return fail(`Not a valid ${name} address: the checksum does not match.`);
    if (payload.length !== 21) return fail(`Not a valid ${name} address: wrong length.`);
    if (p2pkh.includes(payload[0])) return ok("Legacy (P2PKH)");
    if (p2sh.includes(payload[0])) return ok("Script (P2SH)");
    return fail(`This is a Base58 address, but not a ${name} one.`);
  };
}

function evmChecker(addr) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return fail("An EVM address is 0x followed by 40 hex characters.");
  const hex = addr.slice(2);
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) {
    return ok("EVM account", {
      checksum: "none",
      notes: ["This address has no EIP-55 checksum (all lowercase or uppercase), so typos can't be detected. Double-check it."],
    });
  }
  const hash = keccak256(new TextEncoder().encode(hex.toLowerCase()));
  for (let i = 0; i < 40; i++) {
    const nibble = (hash[i >> 1] >> (i % 2 ? 0 : 4)) & 0xf;
    const ch = hex[i];
    if (/[a-f]/i.test(ch) && (nibble >= 8) !== (ch === ch.toUpperCase())) {
      return fail("The EIP-55 checksum (the mix of capital letters) is wrong. The address was probably changed or mistyped.");
    }
  }
  return ok("EVM account");
}

const XMR_PREFIXES = {
  18: ["Standard address", "mainnet"],
  19: ["Integrated address", "mainnet"],
  42: ["Subaddress", "mainnet"],
  24: ["Standard address", "stagenet"],
  25: ["Integrated address", "stagenet"],
  36: ["Subaddress", "stagenet"],
  53: ["Standard address", "testnet"],
  54: ["Integrated address", "testnet"],
  63: ["Subaddress", "testnet"],
};

function moneroChecker(addr) {
  if (addr.length !== 95 && addr.length !== 106) {
    return fail("A Monero address is 95 characters (or 106 for an integrated address).");
  }
  const raw = moneroBase58Decode(addr);
  if (!raw) return fail("Not valid Monero Base58.");
  const body = raw.slice(0, -4);
  const sum = keccak256(body);
  for (let i = 0; i < 4; i++) if (sum[i] !== raw[raw.length - 4 + i]) return fail("The Monero checksum does not match. The address was probably mistyped or cut off.");
  // The network prefix is a varint; every Monero prefix above fits in one byte.
  const info = XMR_PREFIXES[body[0]];
  if (!info) return fail("Unknown Monero network prefix.");
  const [type, network] = info;
  const expectedLen = type === "Integrated address" ? 73 : 65;
  if (body.length !== expectedLen) return fail("Wrong length for this kind of Monero address.");
  const notes = [];
  if (network !== "mainnet") notes.push(`This is a ${network} address. Never send real XMR to it.`);
  if (type === "Integrated address") notes.push("Integrated addresses carry a built-in payment ID. Some services only accept standard addresses or subaddresses.");
  return { type, network, checksum: "verified", notes };
}

function zcashChecker(addr) {
  const lower = addr.toLowerCase();
  const shieldedNote =
    "Many exchanges and instant swap services pay ZEC only to a transparent address (t1 or t3). Check before you use this address as a payout address.";
  if (lower.startsWith("u1")) {
    const dec = bech32Decode(addr, Infinity);
    if (!dec || dec.hrp !== "u" || dec.variant !== "bech32m") return fail("Invalid Zcash unified address checksum.");
    return ok("Unified address (u1)", {
      notes: ["Checksum verified. The receivers inside a unified address are not unpacked by this check.", shieldedNote],
    });
  }
  if (lower.startsWith("zs1")) {
    const dec = bech32Decode(addr);
    const bytes = dec && dec.hrp === "zs" && dec.variant === "bech32" && convertBits(dec.data, 5, 8, false);
    if (!bytes || bytes.length !== 43) return fail("Invalid Zcash Sapling address.");
    return ok("Shielded Sapling (zs)", { notes: [shieldedNote] });
  }
  if (lower.startsWith("tex1")) {
    const dec = bech32Decode(addr);
    const bytes = dec && dec.hrp === "tex" && dec.variant === "bech32m" && convertBits(dec.data, 5, 8, false);
    if (!bytes || bytes.length !== 20) return fail("Invalid Zcash TEX address.");
    return ok("Transparent-source-only (TEX)", {
      notes: ["TEX addresses (ZIP 320) only accept funds sent from transparent addresses. Some wallets don't support them yet."],
    });
  }
  const payload = base58CheckDecode(addr);
  if (!payload) return fail("Not a valid Zcash address: the checksum does not match.");
  if (payload.length === 22 && payload[0] === 0x1c && payload[1] === 0xb8) return ok("Transparent (t1)");
  if (payload.length === 22 && payload[0] === 0x1c && payload[1] === 0xbd) return ok("Transparent script (t3)");
  if (payload.length === 66 && payload[0] === 0x16 && payload[1] === 0x9a) {
    return ok("Sprout (zc)", { notes: ["Sprout addresses are deprecated and most wallets can no longer send to them."] });
  }
  return fail("This is a Base58 address, but not a Zcash one.");
}

function bchChecker(addr) {
  if (/^[13]/.test(addr)) {
    const legacy = utxoChecker({ p2pkh: [0x00], p2sh: [0x05], name: "Bitcoin Cash" })(addr);
    if (legacy.error) return legacy;
    return {
      ...legacy,
      notes: ["Legacy format, which Bitcoin addresses also use. Make sure you mean Bitcoin Cash. The CashAddr format (bitcoincash:q…) is safer."],
    };
  }
  const dec = cashaddrDecode(addr);
  if (!dec) return fail("Not a valid Bitcoin Cash CashAddr: the checksum does not match.");
  return ok(dec.type === "p2pkh" ? "CashAddr (P2PKH)" : "CashAddr (P2SH)");
}

function tronChecker(addr) {
  const payload = base58CheckDecode(addr);
  if (!payload) return fail("Not a valid TRON address: the checksum does not match.");
  if (payload.length !== 21 || payload[0] !== 0x41) return fail("Not a TRON address (it should start with T).");
  return ok("TRON account");
}

function solanaChecker(addr) {
  if (addr.length < 32 || addr.length > 44) return fail("A Solana address is 32 to 44 Base58 characters.");
  const raw = base58Decode(addr);
  if (!raw || raw.length !== 32) return fail("Not a valid Solana address: it doesn't decode to a 32-byte public key.");
  return ok("Solana account", {
    checksum: "none",
    notes: ["Solana addresses have no checksum, so this only confirms the format. Double-check the characters."],
  });
}

function rippleChecker(addr) {
  if (!addr.startsWith("r")) return fail("A classic XRP address starts with r.");
  const payload = base58CheckDecode(addr, XRP_ALPHABET);
  if (!payload || payload.length !== 21 || payload[0] !== 0x00) return fail("Not a valid XRP address: the checksum does not match.");
  return ok("Classic address", {
    notes: ["If you are sending to an exchange, it may also need a destination tag."],
  });
}

function stellarChecker(addr) {
  if (!/^G[A-Z2-7]{55}$/.test(addr)) return fail("A Stellar account address is 56 characters starting with G.");
  const raw = base32Decode(addr);
  if (!raw || raw.length !== 35 || raw[0] !== 6 << 3) return fail("Not a valid Stellar address.");
  const crc = crc16xmodem(raw.slice(0, 33));
  if ((raw[33] | (raw[34] << 8)) !== crc) return fail("The Stellar checksum does not match.");
  return ok("Stellar account", { notes: ["If you are sending to an exchange, it may also need a memo."] });
}

function tonChecker(addr) {
  if (/^-?\d+:[0-9a-fA-F]{64}$/.test(addr)) {
    return ok("Raw address", { checksum: "none", notes: ["Raw TON addresses have no checksum. Double-check it."] });
  }
  if (addr.length !== 48) return fail("A TON address is 48 characters (or the raw 0:… form).");
  const raw = base64Decode(addr);
  if (!raw || raw.length !== 36) return fail("Not a valid TON address.");
  const crc = crc16xmodem(raw.slice(0, 34));
  if (((raw[34] << 8) | raw[35]) !== crc) return fail("The TON checksum does not match.");
  const flags = raw[0];
  const testnet = (flags & 0x80) !== 0;
  const tag = flags & 0x7f;
  if (tag !== 0x11 && tag !== 0x51) return fail("Unknown TON address flags.");
  const notes = [];
  if (testnet) notes.push("This is a testnet address. Never send real TON to it.");
  if (tag === 0x51) notes.push("Non-bounceable address (usually starts with UQ), the right form for wallets.");
  return {
    type: tag === 0x11 ? "Bounceable address" : "Non-bounceable address",
    network: testnet ? "testnet" : "mainnet",
    checksum: "verified",
    notes,
  };
}

function cardanoChecker(addr) {
  if (!addr.startsWith("addr1")) return fail("Only Shelley-era Cardano addresses (addr1…) are checked.");
  const dec = bech32Decode(addr, Infinity);
  if (!dec || dec.hrp !== "addr" || dec.variant !== "bech32") return fail("Not a valid Cardano address: the checksum does not match.");
  const bytes = convertBits(dec.data, 5, 8, false);
  if (!bytes || bytes.length < 29) return fail("Not a valid Cardano address: wrong length.");
  const header = bytes[0] >> 4;
  if ((bytes[0] & 0x0f) !== 1) return fail("This Cardano address is not for mainnet.");
  const types = { 0: "Base address", 1: "Base address", 2: "Base address", 3: "Base address", 4: "Pointer address", 5: "Pointer address", 6: "Enterprise address", 7: "Enterprise address" };
  if (!(header in types)) return fail("Unknown Cardano address type.");
  return ok(types[header]);
}

const dogeCheck = utxoChecker({ p2pkh: [0x1e], p2sh: [0x16], name: "Dogecoin" });

export const COINS = {
  btc: { name: "Bitcoin", symbol: "BTC", check: utxoChecker({ p2pkh: [0x00], p2sh: [0x05], hrp: "bc", testHrp: "tb", name: "Bitcoin" }) },
  xmr: { name: "Monero", symbol: "XMR", check: moneroChecker },
  zec: { name: "Zcash", symbol: "ZEC", check: zcashChecker },
  eth: { name: "Ethereum (EVM)", symbol: "ETH", check: evmChecker, family: ["Ethereum", "BNB Smart Chain", "Polygon", "Arbitrum", "Optimism", "Base", "Avalanche C-Chain"] },
  ltc: { name: "Litecoin", symbol: "LTC", check: utxoChecker({ p2pkh: [0x30], p2sh: [0x32, 0x05], hrp: "ltc", testHrp: "tltc", name: "Litecoin" }) },
  trx: { name: "TRON", symbol: "TRX", check: tronChecker },
  sol: { name: "Solana", symbol: "SOL", check: solanaChecker },
  doge: { name: "Dogecoin", symbol: "DOGE", check: dogeCheck },
  dash: { name: "Dash", symbol: "DASH", check: utxoChecker({ p2pkh: [0x4c], p2sh: [0x10], name: "Dash" }) },
  bch: { name: "Bitcoin Cash", symbol: "BCH", check: bchChecker },
  xrp: { name: "XRP Ledger", symbol: "XRP", check: rippleChecker },
  xlm: { name: "Stellar", symbol: "XLM", check: stellarChecker },
  ton: { name: "TON", symbol: "TON", check: tonChecker },
  ada: { name: "Cardano", symbol: "ADA", check: cardanoChecker },
};

// Tokens validate exactly like the chain they live on.
export const ALIASES = {
  usdt: "eth", usdc: "eth", usdterc20: "eth", usdcerc20: "eth", bnb: "eth", bnbbsc: "eth", bsc: "eth",
  matic: "eth", pol: "eth", arb: "eth", op: "eth", base: "eth", avax: "eth",
  usdttrc20: "trx", usdtsol: "sol", usdcsol: "sol",
  bitcoin: "btc", monero: "xmr", zcash: "zec", ethereum: "eth", litecoin: "ltc", tron: "trx", solana: "sol",
  dogecoin: "doge", ripple: "xrp", stellar: "xlm", cardano: "ada", bitcoincash: "bch",
};

