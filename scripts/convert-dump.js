// Converts the relevant tables from a mysqldump file into SQLite/D1-compatible SQL.
const fs = require("fs");
const crypto = require("crypto");

const PBKDF2_ITERATIONS = 100000;

function hashPassword(plaintext) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(plaintext, salt, PBKDF2_ITERATIONS, 32, "sha256");
  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt.toString("hex")}$${hash.toString("hex")}`;
}

const SRC = "C:/repo/bsperanta/localhost.sql";
const OUT = "C:/repo/bsperanta-static/d1/data.sql";

const TABLES = ["history", "users", "SONGS", "SONGS_METRICS", "SONGS_SELECTED", "SONG_CHORDS_NEW"];

const SCHEMA = `
DROP TABLE IF EXISTS history;
CREATE TABLE history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user TEXT NOT NULL,
  ipaddress TEXT NOT NULL,
  time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  user_title TEXT NOT NULL,
  permission TEXT NOT NULL,
  date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS SONGS;
CREATE TABLE SONGS (
  songId INTEGER PRIMARY KEY,
  songName TEXT NOT NULL UNIQUE,
  songContent TEXT NOT NULL,
  songType TEXT DEFAULT 'other',
  songIsActive INTEGER NOT NULL DEFAULT 1,
  lastUpdated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  addDateTime TEXT NOT NULL
);

DROP TABLE IF EXISTS SONGS_METRICS;
CREATE TABLE SONGS_METRICS (
  songId INTEGER NOT NULL,
  sangDateTime TEXT NOT NULL
);

DROP TABLE IF EXISTS SONGS_SELECTED;
CREATE TABLE SONGS_SELECTED (
  songId INTEGER NOT NULL,
  category TEXT NOT NULL,
  songOrder INTEGER NOT NULL,
  lastUpdateTime TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS SONG_CHORDS_NEW;
CREATE TABLE SONG_CHORDS_NEW (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  songId INTEGER NOT NULL,
  stanzaNumber INTEGER NOT NULL,
  lineNumber INTEGER NOT NULL,
  chords TEXT NOT NULL,
  updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(songId, stanzaNumber, lineNumber)
);
`;

const text = fs.readFileSync(SRC, "utf8");

// Pull out every VALUES blob for "INSERT INTO `table` (...) VALUES\n ... ;" in the dump.
function extractInsertBlocks(table) {
  const marker = `INSERT INTO \`${table}\` (`;
  const blocks = [];
  let searchFrom = 0;
  while (true) {
    const start = text.indexOf(marker, searchFrom);
    if (start === -1) break;
    const valuesIdx = text.indexOf("VALUES", start);
    const colsEnd = text.indexOf(")", start);
    const columns = text.slice(start + marker.length, colsEnd);
    let i = text.indexOf("(", valuesIdx);
    let depth = 0,
      inStr = false;
    let bodyStart = i;
    let end = -1;
    for (; i < text.length; i++) {
      const c = text[i];
      if (inStr) {
        if (c === "\\") {
          i++; // skip escaped char
          continue;
        }
        if (c === "'") inStr = false;
        continue;
      }
      if (c === "'") {
        inStr = true;
        continue;
      }
      if (c === "(") depth++;
      else if (c === ")") {
        depth--;
        if (depth === 0) {
          // peek next non-space char
          let j = i + 1;
          while (text[j] === "," || text[j] === "\n" || text[j] === "\r" || text[j] === " ") j++;
          if (text[j] === ";") {
            end = i + 1;
            break;
          }
        }
      }
    }
    const body = text.slice(bodyStart, end);
    blocks.push({ columns: columns.split(",").map((s) => s.trim().replace(/`/g, "")), body });
    searchFrom = end;
  }
  return blocks;
}

// Split top-level tuples "(...)" from the VALUES body, respecting quoted strings.
function splitTuples(body) {
  const tuples = [];
  let depth = 0,
    inStr = false,
    start = -1;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (inStr) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === "'") inStr = false;
      continue;
    }
    if (c === "'") {
      inStr = true;
      continue;
    }
    if (c === "(") {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (c === ")") {
      depth--;
      if (depth === 0) tuples.push(body.slice(start, i));
    }
  }
  return tuples;
}

// Split one tuple's fields on top-level commas, respecting quoted strings.
function splitFields(tuple) {
  const fields = [];
  let depth = 0,
    inStr = false,
    start = 0;
  for (let i = 0; i < tuple.length; i++) {
    const c = tuple[i];
    if (inStr) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === "'") inStr = false;
      continue;
    }
    if (c === "'") {
      inStr = true;
      continue;
    }
    if (c === ",") {
      fields.push(tuple.slice(start, i));
      start = i + 1;
    }
  }
  fields.push(tuple.slice(start));
  return fields.map((f) => f.trim());
}

// Decode a MySQL-dump string literal 'abc\'s \n here' into the raw JS string.
function decodeMysqlString(field) {
  const inner = field.slice(1, -1); // strip surrounding quotes
  let out = "";
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === "\\") {
      const n = inner[i + 1];
      i++;
      if (n === "n") out += "\n";
      else if (n === "r") out += "\r";
      else if (n === "t") out += "\t";
      else if (n === "0") out += "\0";
      else if (n === "Z") out += "\x1a";
      else if (n === "\\") out += "\\";
      else if (n === "'") out += "'";
      else if (n === '"') out += '"';
      else out += n;
    } else {
      out += c;
    }
  }
  return out;
}

// Re-encode a raw JS string as a SQLite string literal (double up single quotes).
function encodeSqliteString(s) {
  return "'" + s.replace(/'/g, "''") + "'";
}

function convertField(field) {
  if (field === "NULL") return "NULL";
  if (/^-?\d+(\.\d+)?$/.test(field)) return field;
  if (field.startsWith("'") && field.endsWith("'")) {
    return encodeSqliteString(decodeMysqlString(field));
  }
  return field;
}

let outSql = SCHEMA + "\n";

for (const table of TABLES) {
  const blocks = extractInsertBlocks(table);
  if (blocks.length === 0) {
    console.error(`No INSERT found for ${table}`);
    continue;
  }
  let rowCount = 0;
  for (const extracted of blocks) {
    const tuples = splitTuples(extracted.body);
    const colList = extracted.columns.join(", ");
    const pwIdx = table === "users" ? extracted.columns.indexOf("password") : -1;
    for (const tuple of tuples) {
      const rawFields = splitFields(tuple);
      const fields = rawFields.map(convertField);
      if (pwIdx !== -1) {
        const plaintext = decodeMysqlString(rawFields[pwIdx]).trim();
        fields[pwIdx] = encodeSqliteString(hashPassword(plaintext));
      }
      outSql += `INSERT INTO ${table} (${colList}) VALUES (${fields.join(", ")});\n`;
      rowCount++;
    }
  }
  console.log(`${table}: ${rowCount} rows (${blocks.length} insert blocks)`);
}

fs.mkdirSync("C:/repo/bsperanta-static/d1", { recursive: true });
fs.writeFileSync(OUT, outSql, "utf8");
console.log(`Wrote ${OUT} (${(outSql.length / 1024 / 1024).toFixed(2)} MB)`);
