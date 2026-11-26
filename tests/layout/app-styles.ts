import { readFileSync } from "node:fs";

const styles = readFileSync(new URL("../../web/styles.list", import.meta.url), "utf8");
export const appCss = styles.split("\n").map(line => line.trim())
  .filter(line => line && !line.startsWith("#"))
  .map(line => readFileSync(new URL(`../../${line}`, import.meta.url), "utf8"))
  .join("\n");
