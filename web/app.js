// Page script for ghostswap.io/tools/crypto-address-checker/. Everything runs locally.

import { validate, detect, guessCoin, supportedCoins } from "./index.js";

// Pair pages on ghostswap.io to suggest after a valid result.
const SWAP_LINKS = {
  btc: ["btc-xmr", "Swap BTC to XMR"],
  xmr: ["btc-xmr", "Get XMR for BTC"],
  zec: ["btc-zec", "Get ZEC for BTC"],
  eth: ["eth-xmr", "Swap ETH to XMR"],
  ltc: ["ltc-xmr", "Swap LTC to XMR"],
  sol: ["btc-sol", "Get SOL for BTC"],
  trx: ["btc-trx", "Get TRX for BTC"],
  xrp: ["btc-xrp", "Get XRP for BTC"],
  xlm: ["btc-xlm", "Get XLM for BTC"],
  dash: ["btc-dash", "Get DASH for BTC"],
  doge: ["doge-btc", "Swap DOGE to BTC"],
  bch: ["bch-btc", "Swap BCH to BTC"],
  ada: ["ada-usdt20", "Swap ADA to USDT"],
};

const $ = (id) => document.getElementById(id);
const form = $("form");
const input = $("addr");
const select = $("coin");
const out = $("result");

for (const c of supportedCoins()) {
  const opt = document.createElement("option");
  opt.value = c.id;
  opt.textContent = `${c.name} (${c.symbol})`;
  select.append(opt);
}

const params = new URLSearchParams(location.search);
if (params.get("coin") && [...select.options].some((o) => o.value === params.get("coin"))) {
  select.value = params.get("coin");
}

function el(tag, attrs = {}, text) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text != null) node.textContent = text;
  return node;
}

function idFor(symbol) {
  return supportedCoins().find((c) => c.symbol === symbol)?.id;
}

function render(res, others = []) {
  out.replaceChildren();
  out.className = `result show ${res.valid ? "ok" : "bad"}`;
  out.append(el("p", { class: "verdict" }, res.valid ? `✓ Valid ${res.name} address` : `✗ Not a valid ${res.name} address`));

  if (!res.valid) {
    out.append(el("p", {}, res.error));
    return;
  }

  const dl = el("dl");
  const rows = [
    ["Coin", `${res.name} (${res.coin})`],
    ["Type", res.type],
    ["Network", res.network],
    ["Checksum", res.checksum === "verified" ? "Verified" : "None in this format (format check only)"],
  ];
  for (const [k, v] of rows) dl.append(el("dt", {}, k), el("dd", {}, v));
  out.append(dl);

  if (res.notes.length) {
    const ul = el("ul");
    for (const n of res.notes) ul.append(el("li", { class: "warn" }, n));
    out.append(ul);
  }
  if (others.length) {
    out.append(el("p", { class: "also" }, `This format is also valid for: ${others.map((o) => o.name).join(", ")}. Make sure you pick the right one.`));
  }
  const link = SWAP_LINKS[idFor(res.coin)];
  if (link && res.network === "mainnet") {
    out.append(el("a", { class: "cta", href: `https://ghostswap.io/exchange/${link[0]}/` }, `${link[1]} on GhostSwap, no KYC →`));
  }
}

function check() {
  const address = input.value.trim();
  if (!address) {
    out.className = "result";
    return;
  }
  if (select.value !== "auto") {
    render(validate(address, select.value));
    return;
  }
  const matches = detect(address);
  if (matches.length) {
    render(matches[0], matches.slice(1));
    return;
  }
  const guess = guessCoin(address);
  if (guess) {
    render(validate(address, guess));
  } else {
    out.replaceChildren(
      el("p", { class: "verdict" }, "✗ Not a valid address"),
      el("p", {}, "It doesn't match any supported coin. Check for a missing or extra character, or pick the coin from the list."),
    );
    out.className = "result show bad";
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  check();
});
input.addEventListener("input", () => {
  if (input.value.trim().length > 20) check();
  else out.className = "result";
});
select.addEventListener("change", check);
