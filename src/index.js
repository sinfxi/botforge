const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}

function randomId() {
  return crypto.randomUUID();
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function passwordHash(password, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 310000, hash: "SHA-256" }, material, 256);
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function readCookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  const item = raw.split(";").map((part) => part.trim()).find((part) => part.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : null;
}

async function currentUser(request, env) {
  const token = readCookie(request, "fxi_session");
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT users.id, users.email, users.role, users.status FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?"
  ).bind(tokenHash, new Date().toISOString()).first();
  return row && row.status === "active" ? row : null;
}

async function handleApi(request, env, url) {
  if (!env.DB) return json({ error: "Database binding is not configured." }, 503);

  if (url.pathname === "/api/health" && request.method === "GET") {
    try {
      await env.DB.prepare("SELECT 1").first();
      return json({ ok: true, service: "FXI BotForge", database: "connected" });
    } catch {
      return json({ ok: false, database: "unavailable" }, 503);
    }
  }

  if (url.pathname === "/api/bots" && request.method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, slug, title, description, category, file_size, published_at FROM bots WHERE status = 'published' ORDER BY published_at DESC LIMIT 100"
    ).all();
    return json({ items: results || [] });
  }

  if (url.pathname === "/api/auth/register" && request.method === "POST") {
    const body = await request.json().catch(() => null);
    if (!body || typeof body.email !== "string" || typeof body.password !== "string") return json({ error: "اطلاعات نامعتبر است." }, 400);
    const email = body.email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || body.password.length < 10 || body.password.length > 200) {
      return json({ error: "ایمیل معتبر و رمز عبور حداقل ۱۰ کاراکتری وارد کنید." }, 400);
    }
    const salt = randomId();
    const hash = await passwordHash(body.password, salt);
    try {
      await env.DB.prepare("INSERT INTO users (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)")
        .bind(randomId(), email, hash, salt).run();
      return json({ ok: true, message: "حساب ساخته شد. حالا وارد شوید." }, 201);
    } catch {
      return json({ error: "ساخت حساب انجام نشد؛ ممکن است این ایمیل قبلاً ثبت شده باشد." }, 409);
    }
  }

  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    const body = await request.json().catch(() => null);
    if (!body || typeof body.email !== "string" || typeof body.password !== "string") return json({ error: "اطلاعات ورود نامعتبر است." }, 400);
    const user = await env.DB.prepare("SELECT id, password_hash, password_salt, status FROM users WHERE email = ?")
      .bind(body.email.trim().toLowerCase()).first();
    if (!user || user.status !== "active" || await passwordHash(body.password, user.password_salt) !== user.password_hash) {
      return json({ error: "ایمیل یا رمز عبور اشتباه است." }, 401);
    }
    const token = `${randomId()}.${randomId()}`;
    const days = Math.min(30, Math.max(1, Number(env.SESSION_DAYS) || 14));
    const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    await env.DB.prepare("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
      .bind(randomId(), user.id, await sha256(token), expiresAt).run();
    return json({ ok: true }, 200, { "set-cookie": cookie("fxi_session", token, days * 86400) });
  }

  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    const token = readCookie(request, "fxi_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": cookie("fxi_session", "", 0) });
  }

  if (url.pathname === "/api/me" && request.method === "GET") {
    const user = await currentUser(request, env);
    return user ? json({ user }) : json({ user: null }, 401);
  }

  return json({ error: "مسیر API پیدا نشد." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (error) {
        console.error("API error:", error);
        return json({ error: "خطای داخلی سرور رخ داد." }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
