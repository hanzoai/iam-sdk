// Writes dist/*.d.cts, the declarations for the `require` condition.
//
// tsc emits one .d.ts per source file, and "type": "module" makes TypeScript
// read each of them as an ES module. A consumer that require()s dist/x.cjs is
// typed by its sibling dist/x.d.cts: the same declarations, with every relative
// import naming the .cjs twin, so everything it reaches is CommonJS too.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

const dist = new URL("../dist/", import.meta.url);

for (const name of readdirSync(dist)) {
  if (!name.endsWith(".d.ts")) continue;
  const text = readFileSync(new URL(name, dist), "utf8");
  writeFileSync(
    new URL(name.replace(/\.d\.ts$/, ".d.cts"), dist),
    text.replace(/(["'])(\.\.?\/[^"']*)\.js\1/g, "$1$2.cjs$1"),
  );
}
