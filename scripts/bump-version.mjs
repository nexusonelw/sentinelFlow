import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bumpKind = process.argv[2] || "patch";
const packagePath = path.join(root, "package.json");
const packageLockPath = path.join(root, "package-lock.json");
const tauriConfigPath = path.join(root, "src-tauri", "tauri.conf.json");
const cargoPath = path.join(root, "src-tauri", "Cargo.toml");
const cargoLockPath = path.join(root, "src-tauri", "Cargo.lock");
const releaseLogPath = path.join(root, "release-log.md");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function nextVersion(current, kind) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(current);
  if (!match) throw new Error(`不支持的版本号：${current}`);
  let [major, minor, patch] = match.slice(1).map(Number);
  if (kind === "major") {
    major += 1;
    minor = 0;
    patch = 0;
  } else if (kind === "minor") {
    minor += 1;
    patch = 0;
  } else if (kind === "patch") {
    patch += 1;
  } else {
    throw new Error(`版本递增类型必须是 major、minor 或 patch：${kind}`);
  }
  return `${major}.${minor}.${patch}`;
}

const packageJson = readJson(packagePath);
const previousVersion = packageJson.version;
const version = nextVersion(previousVersion, bumpKind);
packageJson.version = version;
writeJson(packagePath, packageJson);

const packageLock = readJson(packageLockPath);
packageLock.version = version;
if (packageLock.packages?.[""]) packageLock.packages[""].version = version;
writeJson(packageLockPath, packageLock);

const tauriConfig = readJson(tauriConfigPath);
tauriConfig.version = version;
writeJson(tauriConfigPath, tauriConfig);

const cargo = fs.readFileSync(cargoPath, "utf8").replace(
  /(^\[package\][\s\S]*?^version = ")[^"]+("\n)/m,
  `$1${version}$2`
);
fs.writeFileSync(cargoPath, cargo);

const cargoLock = fs.readFileSync(cargoLockPath, "utf8").replace(
  /(\[\[package\]\]\nname = "sentinel-flow"\nversion = ")[^"]+("\n)/,
  `$1${version}$2`
);
fs.writeFileSync(cargoLockPath, cargoLock);

const timestamp = new Date().toISOString();
const entry = `\n## ${timestamp} | v${version}\n\n- 版本从 ${previousVersion} 自动递增为 ${version}（${bumpKind}）。\n- 目标：本地构建 macOS 安装包，并由 GitHub Actions 构建 Windows、macOS、Linux 发布附件。\n- 应用监控数据仍保持本地化；本次云端上传仅指 GitHub Release 安装包分发。\n`;
fs.appendFileSync(releaseLogPath, entry);

console.log(`Sentinel Flow version: ${previousVersion} -> ${version}`);
