// Copies non-TS renderer assets (index.html, styles.css) next to the
// compiled renderer.js in dist-electron/src, since tsc only emits .js.
const fs = require("fs");
const path = require("path");

const srcDir = path.join(__dirname, "..", "src");
const outDir = path.join(__dirname, "..", "dist-electron", "src");

fs.mkdirSync(outDir, { recursive: true });

for (const file of ["index.html", "styles.css", "about.html"]) {
  fs.copyFileSync(path.join(srcDir, file), path.join(outDir, file));
  console.log(`Copied ${file} -> dist-electron/src/${file}`);
}
