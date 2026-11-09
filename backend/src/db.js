import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "..", "data");
const DB_FILE = path.join(DATA_DIR, "db.json");

const KEY_FILE = path.join(DATA_DIR, "master.key");

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadDb() {
  ensureDir();
  if (!fs.existsSync(DB_FILE)) {
    return { providers: [], models: [], settings: {}, usageLogs: [], comparisons: [], findings: [] };
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return { providers: [], models: [], settings: {}, usageLogs: [], comparisons: [], findings: [] };
  }
}

let db = loadDb();

function saveDb() {
  ensureDir();
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

export function getDb() {
  return db;
}

export function saveDbNow() {
  saveDb();
}

export function addUsageLog(entry) {
  db.usageLogs.unshift({ id: crypto.randomUUID(), created_at: new Date().toISOString(), ...entry });
  if (db.usageLogs.length > 2000) db.usageLogs.length = 2000;
  saveDb();
}

// ---------- Encryption for API keys ----------

function getMasterKey() {
  ensureDir();
  if (fs.existsSync(KEY_FILE)) {
    return Buffer.from(fs.readFileSync(KEY_FILE, "utf8").trim(), "hex");
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, key.toString("hex"), { mode: 0o600 });
  return key;
}

const masterKey = getMasterKey();

export function encryptSecret(plain) {
  if (!plain) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, iv);
  const enc = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`;
}

export function decryptSecret(payload) {
  if (!payload || !payload.startsWith("v1:")) return null;
  const [, ivHex, tagHex, dataHex] = payload.split(":");
  const decipher = crypto.createDecipheriv("aes-256-gcm", masterKey, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]).toString("utf8");
}
