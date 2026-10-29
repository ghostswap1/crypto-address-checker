// Builds the static page into dist/: index.html plus the library as ES modules.
// Upload dist/ to ghostswap.io/tools/crypto-address-checker/.
import { mkdirSync, copyFileSync, readdirSync, rmSync } from "node:fs";

const out = new URL("../dist/", import.meta.url);
rmSync(out, { recursive: true, force: true });
mkdirSync(new URL("js/", out), { recursive: true });
copyFileSync(new URL("../web/index.html", import.meta.url), new URL("index.html", out));
copyFileSync(new URL("../web/app.js", import.meta.url), new URL("js/app.js", out));
for (const f of readdirSync(new URL("../src/", import.meta.url))) {
  copyFileSync(new URL(`../src/${f}`, import.meta.url), new URL(`js/${f}`, out));
}
console.log("Built dist/");
