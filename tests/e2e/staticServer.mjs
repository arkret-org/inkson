import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";

const [publicDirectoryArgument, portArgument] = process.argv.slice(2);
if (!publicDirectoryArgument || !portArgument) {
  throw new Error("usage: node staticServer.mjs <public-directory> <port>");
}

const publicDirectory = resolve(publicDirectoryArgument);
const port = Number.parseInt(portArgument, 10);
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error(`invalid port: ${portArgument}`);
}

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".wasm", "application/wasm"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

async function existingFile(pathname) {
  const candidate = normalize(join(publicDirectory, pathname));
  if (
    candidate !== publicDirectory &&
    !candidate.startsWith(`${publicDirectory}${sep}`)
  ) {
    return null;
  }
  try {
    return (await stat(candidate)).isFile() ? candidate : null;
  } catch {
    return null;
  }
}

const server = createServer(async (request, response) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" });
    response.end();
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(
      new URL(request.url ?? "/", "http://localhost").pathname,
    );
  } catch {
    response.writeHead(400);
    response.end();
    return;
  }

  const requestedFile = await existingFile(pathname.replace(/^\/+/, ""));
  const file =
    requestedFile ??
    (extname(pathname) ? null : await existingFile("index.html"));
  if (!file) {
    response.writeHead(404, { "Cache-Control": "no-store" });
    response.end();
    return;
  }

  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Type":
      contentTypes.get(extname(file)) ?? "application/octet-stream",
  });
  if (request.method === "HEAD") {
    response.end();
    return;
  }
  createReadStream(file).pipe(response);
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(
    `Inkson E2E static build ready on http://127.0.0.1:${port}\n`,
  );
});
