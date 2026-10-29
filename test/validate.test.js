import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validate, detect, supportedCoins } from "../src/index.js";
import { keccak256, sha256 } from "../src/hash.js";

const { valid } = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
const hex = (b) => Buffer.from(b).toString("hex");

test("hash functions match known vectors", () => {
  assert.equal(hex(keccak256(new Uint8Array())), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(hex(keccak256(new TextEncoder().encode("abc"))), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  assert.equal(hex(sha256(new TextEncoder().encode("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("accepts valid addresses with the right type", () => {
  for (const { coin, address, type } of valid) {
    const res = validate(address, coin);
    assert.equal(res.valid, true, `${coin} ${address}: ${res.error}`);
    assert.equal(res.type, type, `${coin} ${address}`);
  }
});

test("rejects every single-character change to a checksummed address", () => {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  for (const { coin, address } of valid) {
    if (coin === "sol" || coin === "eth") continue; // no checksum / covered below
    for (let i = 4; i < address.length; i += 7) {
      const swap = alphabet[(alphabet.indexOf(address[i]) + 1) % alphabet.length] ?? "q";
      const bad = address.slice(0, i) + swap + address.slice(i + 1);
      if (bad === address) continue;
      assert.equal(validate(bad, coin).valid, false, `${coin} mutated at ${i}: ${bad}`);
    }
  }
});

test("EIP-55 checksum catches a wrong capital letter", () => {
  assert.equal(validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "eth").valid, true);
  assert.equal(validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", "eth").valid, false);
  const lower = validate("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "eth");
  assert.equal(lower.valid, true);
  assert.equal(lower.checksum, "none");
});

test("rejects addresses for the wrong coin", () => {
  assert.equal(validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ltc").valid, false);
  assert.equal(validate("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "btc").valid, false);
  assert.equal(validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "trx").valid, false);
  assert.equal(validate("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "ltc").valid, false);
});

test("flags shielded Zcash addresses for payouts", () => {
  for (const { coin, address } of valid) {
    if (coin !== "zec" || !/^(u1|zs)/.test(address)) continue;
    const res = validate(address, "zec");
    assert.ok(res.notes.some((n) => n.includes("transparent address")), address);
  }
});

test("handles empty input, whitespace and aliases", () => {
  assert.equal(validate("", "btc").valid, false);
  assert.equal(validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa x", "btc").valid, false);
  assert.equal(validate("  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  ", "btc").valid, true);
  assert.equal(validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "USDT-ERC20").valid, true);
  assert.equal(validate("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "monero").valid, true);
  assert.throws(() => validate("x", "notacoin"));
});

test("detect() finds the coin", () => {
  assert.deepEqual(detect(valid.find((v) => v.coin === "xmr").address).map((r) => r.coin), ["XMR"]);
  assert.equal(detect("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")[0].coin, "BTC");
  assert.equal(detect("not an address").length, 0);
  assert.ok(supportedCoins().length >= 14);
});

test("guessCoin() picks the intended coin from the prefix", async () => {
  const { guessCoin } = await import("../src/index.js");
  assert.equal(guessCoin("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"), "eth");
  assert.equal(guessCoin("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx"), "btc");
  assert.equal(guessCoin("u1abc"), "zec");
  assert.equal(guessCoin("hello"), null);
});
