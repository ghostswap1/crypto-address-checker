# crypto-address-checker

Offline, dependency-free crypto address validation for JavaScript. It recomputes each address's real checksum (Base58Check, Bech32/Bech32m, Monero Keccak-256, EIP-55, CashAddr, CRC-16), so a single mistyped character is caught. Nothing is sent over the network.

**Try it in your browser:** [ghostswap.io/tools/crypto-address-checker](https://ghostswap.io/tools/crypto-address-checker/)

## Supported coins

| Coin | Formats | Checksum |
|---|---|---|
| Bitcoin (BTC) | `1…`, `3…`, `bc1q…` (SegWit), `bc1p…` (Taproot), testnet `tb1…` | Base58Check, Bech32, Bech32m |
| Monero (XMR) | standard `4…`, subaddress `8…`, integrated; mainnet, stagenet, testnet | Keccak-256 |
| Zcash (ZEC) | `t1…`, `t3…`, Sapling `zs1…`, unified `u1…`, TEX `tex1…`, Sprout `zc…` | Base58Check, Bech32, Bech32m |
| Ethereum and EVM chains | `0x…` (ETH, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche C-Chain, ERC-20) | EIP-55 |
| Litecoin (LTC) | `L…`, `M…`, `3…`, `ltc1…` | Base58Check, Bech32 |
| TRON (TRX) | `T…` (also TRC-20 tokens) | Base58Check |
| Solana (SOL) | Base58 public key | none (format only) |
| Dogecoin (DOGE) | `D…`, `9…`, `A…` | Base58Check |
| Dash (DASH) | `X…`, `7…` | Base58Check |
| Bitcoin Cash (BCH) | CashAddr `bitcoincash:q…`/`p…`, legacy | CashAddr, Base58Check |
| XRP | classic `r…` | Base58Check (XRP alphabet) |
| Stellar (XLM) | `G…` | CRC-16 |
| TON | `EQ…`, `UQ…`, raw `0:…` | CRC-16 |
| Cardano (ADA) | Shelley `addr1…` | Bech32 |

## Usage

Not on npm yet. Clone this repo and import from `src/index.js`:

```js
import { validate, detect } from "./src/index.js";

validate("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "xmr");
// { valid: true, coin: "XMR", name: "Monero", type: "Standard address",
//   network: "mainnet", checksum: "verified", notes: [] }

validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", "eth");
// { valid: false, ..., error: "The EIP-55 checksum (the mix of capital letters) is wrong. ..." }

detect("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
// [ { valid: true, coin: "BTC", type: "SegWit (P2WPKH)", ... } ]
```

`coin` accepts tickers, names and common token aliases: `"btc"`, `"monero"`, `"usdt-trc20"`, `"usdt-erc20"`, `"bsc"`.

Each result has:

- `valid`: whether the address is correctly formed for that coin
- `type`, `network`: what kind of address it is (`mainnet`, `testnet`, `stagenet`)
- `checksum`: `"verified"`, or `"none"` when the format has no checksum (Solana, raw TON, all-lowercase EVM)
- `notes`: warnings worth showing a user, e.g. Zcash shielded addresses that many services can't pay out to
- `error`: why an invalid address failed

## What "valid" means

A valid address is correctly formed and its checksum matches. It does not prove who owns it, that the address has ever been used, or that a given service supports that network. The Zcash unified address check verifies the Bech32m checksum but doesn't unpack the receivers inside.

## Development

```sh
npm test            # node --test, no dependencies
npm run build:web   # builds the static page into dist/
```

The hash functions (SHA-256, Keccak-256) are bundled so the library has zero dependencies and works synchronously in browsers, Node.js, Deno and workers. The tests check them against published vectors, and the validators were cross-checked against independent encoders.

## License

MIT. Made by [GhostSwap](https://ghostswap.io/), a no-KYC crypto exchange.
