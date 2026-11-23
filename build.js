#!/usr/bin/env node
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const DIST = path.join(__dirname, "frontend", "dist");
const SRC = path.join(__dirname, "frontend", "assets");

// Clean dist
fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(DIST, { recursive: true });

// 1) Minify JS with esbuild
console.log("[1/3] Minifying JS with esbuild...");
execSync(
  `npx esbuild ${path.join(SRC, "app.js")} --bundle --minify --target=es2020 --outfile=${path.join(DIST, "app.min.js")}`,
  { stdio: "inherit" }
);

// 2) Obfuscate the minified JS
console.log("[2/3] Obfuscating JS...");
execSync(
  `npx javascript-obfuscator ${path.join(DIST, "app.min.js")} --output ${path.join(DIST, "app.js")} ` +
    "--compact true " +
    "--control-flow-flattening true " +
    "--control-flow-flattening-threshold 0.5 " +
    "--dead-code-injection true " +
    "--dead-code-injection-threshold 0.2 " +
    "--identifier-names-generator hexadecimal " +
    "--rename-globals true " +
    "--string-array true " +
    "--string-array-calls-transform true " +
    "--string-array-encoding base64 " +
    "--string-array-threshold 0.75 " +
    "--string-array-rotate true " +
    "--string-array-shuffle true " +
    "--split-strings true " +
    "--split-strings-chunk-length 5 " +
    "--transform-object-keys true " +
    "--unicode-escape-sequence false " +
    "--self-defending true",
  { stdio: "inherit" }
);
fs.unlinkSync(path.join(DIST, "app.min.js"));

// 3) Minify CSS
console.log("[3/3] Minifying CSS...");
execSync(
  `npx cleancss -o ${path.join(DIST, "styles.css")} ${path.join(SRC, "styles.css")}`,
  { stdio: "inherit" }
);

// Copy index.html with updated asset paths
console.log("[+] Building index.html...");
let html = fs.readFileSync(path.join(__dirname, "frontend", "index.html"), "utf8");
html = html.replace("/assets/styles.css", "/assets/styles.css");
html = html.replace("/assets/app.js", "/assets/app.js");
// Minify HTML (collapse whitespace)
html = html.replace(/>\s+</g, "><").replace(/\s{2,}/g, " ").trim();
fs.writeFileSync(path.join(DIST, "index.html"), html);

const jsSize = (fs.statSync(path.join(DIST, "app.js")).size / 1024).toFixed(1);
const cssSize = (fs.statSync(path.join(DIST, "styles.css")).size / 1024).toFixed(1);
console.log(`\nBuild complete: dist/app.js (${jsSize} KB), dist/styles.css (${cssSize} KB)`);
