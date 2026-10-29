// crypto-address-checker: offline, dependency-free crypto address validation.
// Nothing is sent over the network; every check runs locally.

import { COINS, ALIASES } from "./coins.js";

export { COINS };

function resolveCoin(coin) {
  const key = String(coin).toLowerCase().replace(/[^a-z0-9]/g, "");
  if (COINS[key]) return key;
  if (ALIASES[key]) return ALIASES[key];
  return null;
}

/**
 * Validates an address for one coin.
 * @param {string} address
 * @param {string} coin  ticker or name, e.g. "btc", "XMR", "usdt-trc20", "monero"
 * @returns {{ valid: boolean, coin: string, name: string, type?: string, network?: string,
 *            checksum?: "verified"|"none", notes: string[], error?: string }}
 */
export function validate(address, coin) {
  const key = resolveCoin(coin);
  if (!key) throw new Error(`Unsupported coin: ${coin}. Supported: ${Object.keys(COINS).join(", ")}`);
  const def = COINS[key];
  const addr = String(address ?? "").trim();
  const base = { coin: def.symbol, name: def.name };
  if (!addr) return { ...base, valid: false, notes: [], error: "Empty address." };
  if (/\s/.test(addr)) return { ...base, valid: false, notes: [], error: "The address contains spaces or line breaks." };
  const res = def.check(addr);
  if (res.error) return { ...base, valid: false, notes: [], error: res.error };
  return { ...base, valid: true, ...res };
}

/**
 * Finds which supported coins an address is valid for.
 * Returns an array of validate() results (only the valid ones), most specific first.
 */
export function detect(address) {
  const out = [];
  for (const key of Object.keys(COINS)) {
    const res = validate(address, key);
    if (res.valid) out.push(res);
  }
  // Solana accepts any 32-byte Base58 string, so prefer a checksummed match when one exists.
  const checksummed = out.filter((r) => r.checksum === "verified");
  return checksummed.length ? [...checksummed, ...out.filter((r) => r.checksum !== "verified")] : out;
}

export const supportedCoins = () =>
  Object.entries(COINS).map(([id, c]) => ({ id, symbol: c.symbol, name: c.name, family: c.family }));

const PREFIX_GUESSES = [
  [/^0x/i, "eth"], [/^(bc1|tb1)/i, "btc"], [/^ltc1/i, "ltc"], [/^(bitcoincash:|[qp][a-z0-9]{41}$)/i, "bch"],
  [/^(u1|zs1|tex1|t1|t3|zc)/i, "zec"], [/^[48][1-9A-HJ-NP-Za-km-z]{90,}/, "xmr"], [/^T/, "trx"], [/^r/, "xrp"],
  [/^G[A-Z2-7]{50,}/, "xlm"], [/^(EQ|UQ|-?\d+:)/, "ton"], [/^addr1/, "ada"], [/^D/, "doge"], [/^X/, "dash"],
  [/^[LM]/, "ltc"], [/^[13]/, "btc"],
];

/** Best guess at which coin an address was meant for, from its prefix (null if no idea). */
export function guessCoin(address) {
  const addr = String(address ?? "").trim();
  for (const [re, coin] of PREFIX_GUESSES) if (re.test(addr)) return coin;
  return null;
}
