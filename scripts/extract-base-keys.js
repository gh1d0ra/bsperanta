#!/usr/bin/env node
// One-off migration: move a song's key out of its title / first lyric line into SONGS.baseKey.
//
//   "Cântaţi toţi de bucurie (D)"   -> line "Cântaţi toţi de bucurie", baseKey "D"
//   "Cu toții ne-adunăm - C"        -> line "Cu toții ne-adunăm",      baseKey "C"
//   "Em" / "(D)" alone on line 1    -> line removed (chord rows renumbered), baseKey "Em" / "D"
//   song name "Ma-ncred in El (A)"  -> name "Ma-ncred in El",          baseKey "A"
//
// It never touches the database. It reads a JSON export and writes a report + SQL to review:
//
//   npx wrangler d1 execute bsperanta-versuri --remote --json \
//       --command "SELECT * FROM SONGS" > songs.json
//   node scripts/extract-base-keys.js songs.json out-dir
//   (review out-dir/report.txt, then)
//   npx wrangler d1 execute bsperanta-versuri --remote --file out-dir/migration.sql

const fs = require("fs");
const path = require("path");

const [inputFile, outDir = "."] = process.argv.slice(2);
if (!inputFile) {
  console.error("usage: node scripts/extract-base-keys.js songs.json [out-dir]");
  process.exit(1);
}

const KEY = "[A-G](?:#|b)?m?";
// Bare keys (no brackets or dash) only when unmistakable: "Dm", "F#", "Bb".
const BARE_KEY = "[A-G](?:[#b]m?|m)";
const ONLY_KEY = new RegExp(`^\\s*\\(?\\s*(${KEY})\\s*\\)?\\s*$`);
const TRAILING_KEY = new RegExp(
  `^(.*?)[\\s,\\-–—]*(?:\\(\\s*(${KEY})\\s*\\)|[-–—]\\s*(${KEY})|\\s(${BARE_KEY}))\\s*$`
);

function trailingKey(text) {
  const m = text.match(TRAILING_KEY);
  if (!m || !m[1].trim()) return null;
  return { rest: m[1].replace(/[\s,\-–—]+$/, ""), key: m[2] || m[3] || m[4] };
}

function sql(str) {
  return "'" + String(str).replace(/'/g, "''") + "'";
}

const raw = JSON.parse(fs.readFileSync(inputFile, "utf8"));
const songs = Array.isArray(raw) && raw[0] && raw[0].results ? raw[0].results : raw;
const hasBaseKeyColumn = songs.length > 0 && "baseKey" in songs[0];
const names = new Set(songs.map((s) => s.songName));

const statements = [];
const report = [];
const skipped = [];
if (!hasBaseKeyColumn) statements.push("ALTER TABLE SONGS ADD COLUMN baseKey TEXT;");

for (const song of songs) {
  if (song.baseKey && String(song.baseKey).trim()) continue; // already set by hand

  const lines = song.songContent.split("\n");
  const first = lines[0].replace(/\r$/, "");
  const cr = lines[0].endsWith("\r") ? "\r" : "";

  let key = null;
  let newLines = lines;
  let chordFix = null; // "stanza" | "line"
  let lineChange = null;

  const only = first.match(ONLY_KEY);
  const trailing = only ? null : trailingKey(first);
  if (only) {
    key = only[1];
    const nextBlank = lines.length > 1 && lines[1].trim() === "";
    newLines = lines.slice(nextBlank ? 2 : 1);
    chordFix = nextBlank ? "stanza" : "line";
    lineChange = `removed line 1 ${JSON.stringify(first)}${nextBlank ? " and the blank line after it" : ""}`;
  } else if (trailing) {
    key = trailing.key;
    newLines = [trailing.rest + cr, ...lines.slice(1)];
    lineChange = `line 1 ${JSON.stringify(first)} -> ${JSON.stringify(trailing.rest)}`;
  }

  let newName = song.songName;
  const nameKey = trailingKey(song.songName);
  const notes = [];
  if (nameKey) {
    if (key && nameKey.key !== key) notes.push(`NOTE: name says ${nameKey.key}, lyrics say ${key}; using ${key}`);
    key = key || nameKey.key;
    if (names.has(nameKey.rest) && nameKey.rest !== song.songName) {
      notes.push(`NAME NOT CHANGED: another song is already called ${JSON.stringify(nameKey.rest)}`);
    } else {
      newName = nameKey.rest;
      names.delete(song.songName);
      names.add(newName);
    }
  }

  if (!key) continue;

  const sets = [`baseKey = ${sql(key)}`];
  if (newLines !== lines) sets.push(`songContent = ${sql(newLines.join("\n"))}`);
  if (newName !== song.songName) sets.push(`songName = ${sql(newName)}`);
  statements.push(`UPDATE SONGS SET ${sets.join(", ")} WHERE songId = ${song.songId};`);

  // Chords are stored per (stanza, line). Removing line 1 shifts the lines after it.
  // Rows move through a +100000 offset so no step collides with the UNIQUE index.
  const id = song.songId;
  if (chordFix === "stanza") {
    statements.push(
      `DELETE FROM SONG_CHORDS_NEW WHERE songId = ${id} AND stanzaNumber = 0;`,
      `UPDATE SONG_CHORDS_NEW SET stanzaNumber = stanzaNumber + 100000 WHERE songId = ${id};`,
      `UPDATE SONG_CHORDS_NEW SET stanzaNumber = stanzaNumber - 100001 WHERE songId = ${id} AND stanzaNumber >= 100000;`
    );
  } else if (chordFix === "line") {
    statements.push(
      `DELETE FROM SONG_CHORDS_NEW WHERE songId = ${id} AND stanzaNumber = 0 AND lineNumber = 1;`,
      `UPDATE SONG_CHORDS_NEW SET lineNumber = lineNumber + 100000 WHERE songId = ${id} AND stanzaNumber = 0;`,
      `UPDATE SONG_CHORDS_NEW SET lineNumber = lineNumber - 100001 WHERE songId = ${id} AND stanzaNumber = 0 AND lineNumber >= 100000;`
    );
  }

  const parts = [`#${id}  key ${key}`];
  if (lineChange) parts.push(`  lyrics: ${lineChange}`);
  if (newName !== song.songName) parts.push(`  name:   ${JSON.stringify(song.songName)} -> ${JSON.stringify(newName)}`);
  if (chordFix) parts.push(`  chords: renumbered (${chordFix === "stanza" ? "stanzas shift up by one" : "verse 1 lines shift up by one"})`);
  notes.forEach((n) => parts.push(`  ${n}`));
  report.push(parts.join("\n"));
}

// Lines that end in something key-like the rules above did not take, for a human to check.
for (const song of songs) {
  if (song.baseKey && String(song.baseKey).trim()) continue;
  const first = song.songContent.split("\n")[0].trim();
  if (report.some((r) => r.startsWith(`#${song.songId} `))) continue;
  if (/\b[A-G][#b]?m?\s*\)?\s*$/.test(first) && /[(\-–—]|\s[A-G]/.test(first)) {
    skipped.push(`#${song.songId}  ${JSON.stringify(first)}`);
  }
}

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "migration.sql"), statements.join("\n") + "\n");
fs.writeFileSync(
  path.join(outDir, "report.txt"),
  `${report.length} of ${songs.length} songs get a base key.\n\n` +
    report.join("\n\n") +
    `\n\nNot changed, but the first line ends in something that may be a key (${skipped.length}):\n` +
    (skipped.join("\n") || "(none)") +
    "\n"
);
console.log(`${report.length} songs to update; ${skipped.length} to check by hand.`);
console.log(`Wrote ${path.join(outDir, "report.txt")} and ${path.join(outDir, "migration.sql")}`);
