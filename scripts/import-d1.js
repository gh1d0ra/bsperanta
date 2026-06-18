// Imports schema + data into D1 via the Cloudflare REST API (no workerd/wrangler needed).
const fs = require("fs");

const ACCOUNT_ID = "75e217a7a7511b2e71e46b414ed227e0";
const DATABASE_ID = "4e0db2b3-88f8-414d-89d8-cfd0f98201be";
const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const ENDPOINT = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/d1/database/${DATABASE_ID}/query`;

async function runSql(sql) {
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ sql }),
  });
  const data = await res.json();
  if (!data.success) {
    console.error("FAILED SQL (first 200 chars):", sql.slice(0, 200));
    console.error(JSON.stringify(data.errors));
    throw new Error("D1 query failed");
  }
  return data;
}

// Split the file into top-level statements on ';', respecting single-quoted strings
// (which may contain embedded raw newlines, e.g. song lyrics) and '' escaped quotes.
function splitStatements(sql) {
  const statements = [];
  let inStr = false;
  let start = 0;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (inStr) {
      if (c === "'") {
        if (sql[i + 1] === "'") {
          i++; // escaped quote, stay in string
        } else {
          inStr = false;
        }
      }
      continue;
    }
    if (c === "'") {
      inStr = true;
      continue;
    }
    if (c === ";") {
      const stmt = sql.slice(start, i).trim();
      if (stmt) statements.push(stmt);
      start = i + 1;
    }
  }
  const tail = sql.slice(start).trim();
  if (tail) statements.push(tail);
  return statements;
}

async function main() {
  const sqlFile = process.argv[2];
  const full = fs.readFileSync(sqlFile, "utf8");
  const statements = splitStatements(full).filter((s) => !s.startsWith("--"));

  const BATCH_SIZE = 100;
  let done = 0;
  for (let i = 0; i < statements.length; i += BATCH_SIZE) {
    const batch = statements.slice(i, i + BATCH_SIZE).join(";\n") + ";";
    await runSql(batch);
    done += Math.min(BATCH_SIZE, statements.length - i);
    console.log(`Progress: ${done}/${statements.length}`);
  }
  console.log("Import complete.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
