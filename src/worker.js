const SESSION_COOKIE = "session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

async function verifyPassword(stored, plaintext) {
  const [scheme, iterStr, saltHex, hashHex] = stored.split("$");
  if (scheme !== "pbkdf2") return false;
  const iterations = parseInt(iterStr, 10);
  const salt = hexToBuf(saltHex);
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(plaintext), "PBKDF2", false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufToHex(derived) === hashHex;
}

async function signSession(payload, secret) {
  const body = btoa(JSON.stringify(payload));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return `${body}.${bufToHex(sig)}`;
}

async function verifySession(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const expected = bufToHex(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
  if (expected !== sig) return null;
  try {
    const payload = JSON.parse(atob(body));
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function getSessionUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  return await verifySession(token, env.SESSION_SECRET);
}

function isAdmin(user) {
  return !!user && typeof user.permission === "string" && user.permission.includes("admin");
}

async function requireAdmin(request, env) {
  const user = await getSessionUser(request, env);
  if (!isAdmin(user)) return null;
  return user;
}

function getRealIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

const ACTIVE_SONG_TYPE_EXCLUDE = ["nastere", "paste", "seceris", "none"];

async function handleApi(request, env, url) {
  const { pathname } = url;
  const method = request.method;

  if (pathname === "/api/me" && method === "GET") {
    const user = await getSessionUser(request, env);
    if (!user) return json({ loggedIn: false });
    return json({ loggedIn: true, username: user.name, title: user.title, permission: user.permission });
  }

  if (pathname === "/api/login" && method === "POST") {
    const { username, password } = await request.json();
    if (!username || !password) return json({ error: "Missing credentials" }, 400);
    const row = await env.DB.prepare(
      "SELECT name, password, user_title, permission FROM users WHERE LOWER(name) = LOWER(?)"
    )
      .bind(username)
      .first();
    if (!row || !(await verifyPassword(row.password, password))) {
      return json({ error: "Numele sau Parola este incorecta!" }, 401);
    }
    const payload = {
      name: row.name,
      title: row.user_title,
      permission: row.permission,
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
    };
    const token = await signSession(payload, env.SESSION_SECRET);
    await env.DB.prepare("INSERT INTO history (user, ipaddress) VALUES (?, ?)")
      .bind(row.name, getRealIp(request))
      .run();
    return json(
      { loggedIn: true, username: row.name, title: row.user_title, permission: row.permission },
      200,
      {
        "Set-Cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`,
      }
    );
  }

  if (pathname === "/api/logout" && method === "POST") {
    return json({ ok: true }, 200, {
      "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    });
  }

  if (pathname === "/api/songs" && method === "GET") {
    const placeholders = ACTIVE_SONG_TYPE_EXCLUDE.map(() => "?").join(",");
    const { results } = await env.DB.prepare(
      `SELECT s.songId, s.songName, s.songType, m.sangCount, m.lastSang
       FROM SONGS s
       LEFT JOIN (
         SELECT songId, COUNT(*) as sangCount, MAX(sangDateTime) as lastSang
         FROM SONGS_METRICS GROUP BY songId
       ) m ON s.songId = m.songId
       WHERE s.songIsActive = 1 AND s.songType NOT IN (${placeholders})
       ORDER BY s.songName`
    )
      .bind(...ACTIVE_SONG_TYPE_EXCLUDE)
      .all();
    return json(results);
  }

  const songMatch = pathname.match(/^\/api\/songs\/(\d+)$/);
  if (songMatch && method === "GET") {
    const songId = parseInt(songMatch[1], 10);
    const song = await env.DB.prepare("SELECT * FROM SONGS WHERE songId = ?").bind(songId).first();
    if (!song) return json({ error: "Not found" }, 404);
    const { results: chords } = await env.DB.prepare(
      "SELECT stanzaNumber, lineNumber, chords FROM SONG_CHORDS_NEW WHERE songId = ? ORDER BY stanzaNumber, lineNumber"
    )
      .bind(songId)
      .all();
    return json({ ...song, chords });
  }

  if (songMatch && method === "PUT") {
    const admin = await requireAdmin(request, env);
    if (!admin) return json({ error: "Unauthorized" }, 401);
    const songId = parseInt(songMatch[1], 10);
    const { content, type } = await request.json();
    await env.DB.prepare(
      "UPDATE SONGS SET songContent = ?, songType = ?, lastUpdated = CURRENT_TIMESTAMP WHERE songId = ?"
    )
      .bind(content, type || "other", songId)
      .run();
    return json({ ok: true });
  }

  const chordsMatch = pathname.match(/^\/api\/songs\/(\d+)\/chords$/);
  if (chordsMatch && method === "POST") {
    const admin = await requireAdmin(request, env);
    if (!admin) return json({ error: "Unauthorized" }, 401);
    const songId = parseInt(chordsMatch[1], 10);
    const { entries } = await request.json();
    for (const e of entries) {
      await env.DB.prepare(
        `INSERT INTO SONG_CHORDS_NEW (songId, stanzaNumber, lineNumber, chords, updated)
         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(songId, stanzaNumber, lineNumber) DO UPDATE SET chords = excluded.chords, updated = CURRENT_TIMESTAMP`
      )
        .bind(songId, e.stanza, e.line, e.chords)
        .run();
    }
    return json({ ok: true });
  }

  const sangMatch = pathname.match(/^\/api\/songs\/(\d+)\/sang$/);
  if (sangMatch && method === "POST") {
    const admin = await requireAdmin(request, env);
    if (!admin) return json({ error: "Unauthorized" }, 401);
    const songId = parseInt(sangMatch[1], 10);
    await env.DB.prepare("INSERT INTO SONGS_METRICS (songId, sangDateTime) VALUES (?, CURRENT_DATE)")
      .bind(songId)
      .run();
    return json({ ok: true });
  }

  if (pathname === "/api/songs" && method === "POST") {
    const admin = await requireAdmin(request, env);
    if (!admin) return json({ error: "Unauthorized" }, 401);
    const { name, content, type } = await request.json();
    if (!name || !content) return json({ error: "Missing fields" }, 400);
    await env.DB.prepare(
      "INSERT INTO SONGS (songName, songContent, songType, songIsActive, addDateTime) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)"
    )
      .bind(name, content, type || "other")
      .run();
    return json({ ok: true });
  }

  if (pathname === "/api/selected" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT s.songId, s.songName FROM SONGS s, SONGS_SELECTED se
       WHERE s.songId = se.songId ORDER BY se.songOrder`
    ).all();
    return json(results);
  }

  if (pathname === "/api/selected" && method === "POST") {
    const admin = await requireAdmin(request, env);
    if (!admin) return json({ error: "Unauthorized" }, 401);
    const { songId } = await request.json();
    const maxRow = await env.DB.prepare("SELECT IFNULL(MAX(songOrder), 0) + 1 as nextOrder FROM SONGS_SELECTED").first();
    await env.DB.prepare("INSERT INTO SONGS_SELECTED (songId, category, songOrder) VALUES (?, '', ?)")
      .bind(songId, maxRow.nextOrder)
      .run();
    return json({ ok: true });
  }

  if (pathname === "/api/selected/reorder" && method === "PUT") {
    const admin = await requireAdmin(request, env);
    if (!admin) return json({ error: "Unauthorized" }, 401);
    const { songIds } = await request.json();
    for (let i = 0; i < songIds.length; i++) {
      await env.DB.prepare("UPDATE SONGS_SELECTED SET songOrder = ? WHERE songId = ?")
        .bind(i + 1, songIds[i])
        .run();
    }
    return json({ ok: true });
  }

  const unselectMatch = pathname.match(/^\/api\/selected\/(\d+)$/);
  if (unselectMatch && method === "DELETE") {
    const admin = await requireAdmin(request, env);
    if (!admin) return json({ error: "Unauthorized" }, 401);
    const songId = parseInt(unselectMatch[1], 10);
    await env.DB.prepare("DELETE FROM SONGS_SELECTED WHERE songId = ?").bind(songId).run();
    return json({ ok: true });
  }

  return json({ error: "Not found" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  },
};
