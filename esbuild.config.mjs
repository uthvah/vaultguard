import esbuild from "esbuild";
import process from "process";

const prod = process.argv[2] === "production";

const ctx = await esbuild.context({
  entryPoints: ["index.js"],
  bundle: true,
  external: ["obsidian"],
  format: "cjs",
  target: "es2018",
  logLevel: "info",
  sourcemap: prod ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
  minify: prod,
});

if (prod) {
  await ctx.rebuild();
  ctx.dispose();
} else {
  await ctx.watch();
  console.log("watching...");
}