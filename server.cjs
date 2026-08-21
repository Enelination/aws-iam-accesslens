const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const DIST = path.join(__dirname, "dist");

const MIME = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const decoded = decodeURIComponent(url.pathname);

  // Block path traversal — reject any path with .. segments
  if (decoded.includes("..")) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  let filePath = path.join(DIST, decoded === "/" ? "index.html" : decoded);

  // Prevent path traversal — ensure resolved path stays inside DIST
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(DIST)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  if (!fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) {
    filePath = path.join(DIST, "index.html");
  }
  const ext = path.extname(filePath);
  res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
});

server.listen(PORT);
