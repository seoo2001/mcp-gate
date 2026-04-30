#!/usr/bin/env node
const { spawnSync } = require("child_process");
const path = require("path");

const platform = process.platform;
const arch = process.arch;
const ext = platform === "win32" ? ".exe" : "";
const pkgName = `mcp-gate-${platform}-${arch}`;

let binaryPath;
try {
  const pkgJsonPath = require.resolve(`${pkgName}/package.json`);
  binaryPath = path.join(path.dirname(pkgJsonPath), "bin", `mcp-gate${ext}`);
} catch (_err) {
  process.stderr.write(
    `mcp-gate: no prebuilt binary for ${platform}-${arch}\n` +
      `Install Go and run: go install github.com/seoo2001/mcp-gate/cmd/mcp-gate@latest\n`,
  );
  process.exit(1);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});
if (result.error) {
  process.stderr.write(`mcp-gate: ${result.error.message}\n`);
  process.exit(1);
}
process.exit(result.status ?? 1);
