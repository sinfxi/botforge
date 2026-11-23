const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const MAX_UPLOAD = 5 * 1024 * 1024;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();
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
function safeText(value, max) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function safeFilename(value) {
  return safeText(value, 120).replace(/[^\p{L}\p{N}._ -]/gu, "_").replace(/\s+/g, "_");
}
function slugify(value) {
  const base = value.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
  return base || id().slice(0, 8);
}
async function currentUser(request, env) {
  const token = readCookie(request, "fxi_session");
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT users.id, users.email, users.role, users.status FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?"
  ).bind(await sha256(token), now()).first();
  return row && row.status === "active" ? row : null;
}
async function requireUser(request, env) {
  const user = await currentUser(request, env);
  return user ? { user } : { response: json({ error: "برای ادامه وارد حساب شوید." }, 401) };
}
async function requireAdmin(request, env) {
  const auth = await requireUser(request, env);
  if (auth.response) return auth;
  return ["admin", "owner"].includes(auth.user.role) ? auth : { response: json({ error: "اجازه دسترسی ندارید." }, 403) };
}
function sameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try { return new URL(origin).host === new URL(request.url).host; } catch { return false; }
}
async function audit(env, actor, action, targetType = null, targetId = null, details = null) {
  await env.DB.prepare("INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, details_json) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(id(), actor || null, action, targetType, targetId, details ? JSON.stringify(details) : null).run();
}
async function notify(env, userId, title, body, type = "info") {
  await env.DB.prepare("INSERT INTO notifications (id, user_id, title, body, type) VALUES (?, ?, ?, ?, ?)")
    .bind(id(), userId, title, body, type).run();
}
async function handleApi(request, env, url) {
  if (!env.DB) return json({ error: "Database binding is not configured." }, 503);
  const path = url.pathname;
  const method = request.method;

  if (path === "/api/health" && method === "GET") {
    try {
      await env.DB.prepare("SELECT 1").first();
      return json({ ok: true, service: "FXI BotForge", database: "connected", storage: env.FILES ? "KV configured" : "missing" });
    } catch { return json({ ok: false, database: "unavailable" }, 503); }
  }

  if (path === "/api/auth/bootstrap" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    if (!env.BOOTSTRAP_OWNER_EMAIL || !env.BOOTSTRAP_OWNER_PASSWORD) return json({ error: "تنظیمات اولیه مالک روی سرور تعریف نشده است." }, 503);
    const existing = await env.DB.prepare("SELECT id FROM users WHERE role IN ('owner','admin') LIMIT 1").first();
    if (existing) return json({ error: "حساب مدیر قبلاً ساخته شده است." }, 409);
    const body = await request.json().catch(() => null);
    const email = safeText(body?.email, 254).toLowerCase();
    const password = typeof body?.password === "string" ? body.password : "";
    if (email !== env.BOOTSTRAP_OWNER_EMAIL.toLowerCase() || password !== env.BOOTSTRAP_OWNER_PASSWORD) return json({ error: "اطلاعات راه‌اندازی صحیح نیست." }, 401);
    const salt = id();
    const userId = id();
    await env.DB.prepare("INSERT INTO users (id,email,password_hash,password_salt,role) VALUES (?,?,?,?, 'owner')")
      .bind(userId, email, await passwordHash(password, salt), salt).run();
    await audit(env, userId, "owner.bootstrap", "user", userId);
    return json({ ok: true, message: "حساب مالک ساخته شد؛ اکنون وارد شوید." }, 201);
  }

  if (path === "/api/auth/register" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const body = await request.json().catch(() => null);
    if (!body || typeof body.email !== "string" || typeof body.password !== "string") return json({ error: "اطلاعات نامعتبر است." }, 400);
    const email = body.email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || body.password.length < 10 || body.password.length > 200) return json({ error: "ایمیل معتبر و رمز عبور حداقل ۱۰ کاراکتری وارد کنید." }, 400);
    const salt = id();
    try {
      await env.DB.prepare("INSERT INTO users (id,email,password_hash,password_salt) VALUES (?,?,?,?)")
        .bind(id(), email, await passwordHash(body.password, salt), salt).run();
      return json({ ok: true, message: "حساب ساخته شد. حالا وارد شوید." }, 201);
    } catch { return json({ error: "این ایمیل قبلاً ثبت شده یا ساخت حساب ممکن نیست." }, 409); }
  }

  if (path === "/api/auth/login" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const body = await request.json().catch(() => null);
    if (!body || typeof body.email !== "string" || typeof body.password !== "string") return json({ error: "اطلاعات ورود نامعتبر است." }, 400);
    const user = await env.DB.prepare("SELECT id,password_hash,password_salt,status FROM users WHERE email = ?")
      .bind(body.email.trim().toLowerCase()).first();
    if (!user || user.status !== "active" || await passwordHash(body.password, user.password_salt) !== user.password_hash) return json({ error: "ایمیل یا رمز عبور اشتباه است." }, 401);
    const token = `${id()}.${id()}`;
    const days = Math.min(30, Math.max(1, Number(env.SESSION_DAYS) || 14));
    await env.DB.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)")
      .bind(id(), user.id, await sha256(token), new Date(Date.now() + days * 86400000).toISOString()).run();
    return json({ ok: true }, 200, { "set-cookie": cookie("fxi_session", token, days * 86400) });
  }

  if (path === "/api/auth/logout" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const token = readCookie(request, "fxi_session");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": cookie("fxi_session", "", 0) });
  }

  if (path === "/api/me" && method === "GET") {
    const user = await currentUser(request, env);
    return user ? json({ user }) : json({ user: null }, 401);
  }

  if (path === "/api/bots" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT id,slug,title,description,category,file_size,published_at FROM bots WHERE status='published' ORDER BY published_at DESC LIMIT 100").all();
    return json({ items: results || [] }, 200, { "cache-control": "public, max-age=0, s-maxage=30, stale-while-revalidate=60" });
  }

  if (path === "/api/submissions" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    if (!env.FILES) return json({ error: "ذخیره‌سازی فایل هنوز پیکربندی نشده است." }, 503);
    const form = await request.formData();
    const title = safeText(form.get("title"), 100);
    const description = safeText(form.get("description"), 2000);
    const category = safeText(form.get("category"), 50);
    const rights = form.get("rights") === "on" || form.get("rights") === "true";
    const file = form.get("file");
    if (title.length < 3 || description.length < 10 || !category || !rights || !(file instanceof File)) return json({ error: "عنوان، توضیحات، دسته‌بندی، فایل و تأیید حق انتشار الزامی است." }, 400);
    if (!file.name.toLowerCase().endsWith(".zip") || file.size < 4 || file.size > (Number(env.MAX_UPLOAD_BYTES) || MAX_UPLOAD)) return json({ error: "فقط ZIP با حجم حداکثر ۵ مگابایت پذیرفته می‌شود." }, 400);
    const bytes = await file.arrayBuffer();
    const head = new Uint8Array(bytes.slice(0, 4));
    if (!(head[0] === 0x50 && head[1] === 0x4b && [0x03,0x05,0x07].includes(head[2]) && [0x04,0x06,0x08].includes(head[3]))) return json({ error: "ساختار فایل ZIP معتبر نیست." }, 400);
    const submissionId = id();
    const objectKey = `pending/${auth.user.id}/${submissionId}.zip`;
    await env.FILES.put(objectKey, bytes);
    try {
      await env.DB.prepare("INSERT INTO submissions (id,user_id,title,description,category,object_key,original_filename,file_size,rights_confirmed) VALUES (?,?,?,?,?,?,?,?,1)")
        .bind(submissionId, auth.user.id, title, description, category, objectKey, safeFilename(file.name) || "source.zip", file.size).run();
    } catch (error) {
      await env.FILES.delete(objectKey);
      throw error;
    }
    await audit(env, auth.user.id, "submission.create", "submission", submissionId);
    return json({ ok: true, id: submissionId, message: "سورس برای بررسی مدیر ارسال شد." }, 201);
  }

  if (path === "/api/my/submissions" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const { results } = await env.DB.prepare("SELECT id,title,category,file_size,status,review_note,created_at,reviewed_at FROM submissions WHERE user_id=? ORDER BY created_at DESC LIMIT 50").bind(auth.user.id).all();
    return json({ items: results || [] });
  }

  if (path === "/api/notifications" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const { results } = await env.DB.prepare("SELECT id,title,body,type,read_at,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50").bind(auth.user.id).all();
    return json({ items: results || [] });
  }

  const markRead = path.match(/^\/api\/notifications\/([0-9a-f-]+)\/read$/i);
  if (markRead && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    await env.DB.prepare("UPDATE notifications SET read_at=? WHERE id=? AND user_id=?").bind(now(), markRead[1], auth.user.id).run();
    return json({ ok: true });
  }

  const download = path.match(/^\/api\/bots\/([a-z0-9-]+)\/download$/);
  if (download && method === "GET") {
    const bot = await env.DB.prepare("SELECT title,object_key,original_filename FROM bots WHERE slug=? AND status='published'").bind(download[1]).first();
    if (!bot || !env.FILES) return json({ error: "فایل پیدا نشد." }, 404);
    const object = await env.FILES.get(bot.object_key, "arrayBuffer");
    if (!object) return json({ error: "فایل در دسترس نیست." }, 404);
    await audit(env, null, "bot.download", "bot", download[1]);
    const encodedName = encodeURIComponent(bot.original_filename || "source.zip");
    return new Response(object, { headers: { "content-type": "application/zip", "content-disposition": "attachment; filename=\"source.zip\"; filename*=UTF-8''" + encodedName, "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
  }

  if (path.startsWith("/api/admin/")) {
    const admin = await requireAdmin(request, env);
    if (admin.response) return admin.response;
    if (path === "/api/admin/overview" && method === "GET") {
      const [users, bots, pending, submissions, downloads] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS count FROM users").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM bots WHERE status='published'").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM submissions WHERE status='pending'").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM submissions").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action='bot.download'").first()
      ]);
      return json({ users: users.count, bots: bots.count, pending: pending.count, submissions: submissions.count, downloads: downloads.count });
    }
    if (path === "/api/admin/submissions" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT s.id,s.title,s.description,s.category,s.original_filename,s.file_size,s.status,s.created_at,u.email AS uploader_email FROM submissions s JOIN users u ON u.id=s.user_id ORDER BY CASE s.status WHEN 'pending' THEN 0 ELSE 1 END,s.created_at DESC LIMIT 100").all();
      return json({ items: results || [] });
    }
    const review = path.match(/^\/api\/admin\/submissions\/([0-9a-f-]+)\/(approve|reject)$/i);
    if (review && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
      const submission = await env.DB.prepare("SELECT * FROM submissions WHERE id=? AND status='pending'").bind(review[1]).first();
      if (!submission) return json({ error: "درخواست پیدا نشد یا قبلاً بررسی شده است." }, 404);
      const body = await request.json().catch(() => ({}));
      const decision = review[2].toLowerCase();
      if (decision === "reject") {
        const note = safeText(body?.note, 500);
        await env.DB.prepare("UPDATE submissions SET status='rejected',review_note=?,reviewed_by=?,reviewed_at=? WHERE id=? AND status='pending'")
          .bind(note || "درخواست تأیید نشد.", admin.user.id, now(), submission.id).run();
        await env.FILES?.delete(submission.object_key);
        await notify(env, submission.user_id, "نتیجه بررسی سورس", note || "متأسفانه سورس ارسالی تأیید نشد.", "warning");
        await audit(env, admin.user.id, "submission.reject", "submission", submission.id);
        return json({ ok: true });
      }
      const slug = `${slugify(submission.title)}-${submission.id.slice(0,8)}`;
      const publishedKey = `published/${slug}.zip`;
      const source = await env.FILES?.get(submission.object_key, "arrayBuffer");
      if (!source) return json({ error: "فایل خصوصی درخواست پیدا نشد." }, 409);
      await env.FILES.put(publishedKey, source);
      try {
        await env.DB.prepare("INSERT INTO bots (id,slug,title,description,category,object_key,original_filename,file_size,uploader_id) VALUES (?,?,?,?,?,?,?,?,?)")
          .bind(id(), slug, submission.title, submission.description, submission.category, publishedKey, submission.original_filename, submission.file_size, submission.user_id).run();
        await env.DB.prepare("UPDATE submissions SET status='approved',reviewed_by=?,reviewed_at=? WHERE id=? AND status='pending'")
          .bind(admin.user.id, now(), submission.id).run();
      } catch (error) {
        await env.FILES.delete(publishedKey);
        throw error;
      }
      await env.FILES.delete(submission.object_key);
      await notify(env, submission.user_id, "سورس تو منتشر شد! 🎉", `«${submission.title}» پس از بررسی تأیید و در BotForge منتشر شد.`, "success");
      await audit(env, admin.user.id, "submission.approve", "submission", submission.id, { slug });
      return json({ ok: true, slug });
    }
    if (path === "/api/admin/users" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT id,email,role,status,created_at FROM users ORDER BY created_at DESC LIMIT 200").all();
      return json({ items: results || [] });
    }
    const userStatus = path.match(/^\/api\/admin\/users\/([0-9a-f-]+)\/(suspend|activate)$/i);
    if (userStatus && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
      if (userStatus[1] === admin.user.id) return json({ error: "نمی‌توانی حساب خودت را غیرفعال کنی." }, 400);
      const target = await env.DB.prepare("SELECT id,email,role FROM users WHERE id=?").bind(userStatus[1]).first();
      if (!target) return json({ error: "کاربر پیدا نشد." }, 404);
      if (target.role === "owner" && admin.user.role !== "owner") return json({ error: "فقط مالک می‌تواند حساب مالک را تغییر دهد." }, 403);
      const status = userStatus[2].toLowerCase() === "suspend" ? "suspended" : "active";
      await env.DB.prepare("UPDATE users SET status=?,updated_at=? WHERE id=?").bind(status, now(), target.id).run();
      if (status === "suspended") await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(target.id).run();
      await audit(env, admin.user.id, "user." + status, "user", target.id, { email: target.email });
      return json({ ok: true, status });
    }
    if (path === "/api/admin/bots" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT id,slug,title,category,file_size,status,published_at FROM bots ORDER BY published_at DESC LIMIT 200").all();
      return json({ items: results || [] });
    }
    const archiveBot = path.match(/^\/api\/admin\/bots\/([0-9a-f-]+)\/archive$/i);
    if (archiveBot && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
      const bot = await env.DB.prepare("SELECT id,title,object_key FROM bots WHERE id=? AND status='published'").bind(archiveBot[1]).first();
      if (!bot) return json({ error: "سورس منتشرشده پیدا نشد." }, 404);
      await env.DB.prepare("UPDATE bots SET status='archived' WHERE id=?").bind(bot.id).run();
      await env.FILES?.delete(bot.object_key);
      await audit(env, admin.user.id, "bot.archive", "bot", bot.id, { title: bot.title });
      return json({ ok: true });
    }
    if (path === "/api/admin/audit" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT a.id,a.action,a.target_type,a.target_id,a.details_json,a.created_at,u.email AS actor_email FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 100").all();
      return json({ items: results || [] });
    }
    return json({ error: "مسیر مدیریت پیدا نشد." }, 404);
  }

  return json({ error: "مسیر API پیدا نشد." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await handleApi(request, env, url); }
      catch (error) { console.error("API error:", error); return json({ error: "خطای داخلی سرور رخ داد." }, 500); }
    }
    if (!env.FILES) return new Response("Storage unavailable", { status: 503 });
    const assetPath = url.pathname === "/" ? "/index.html" : url.pathname;
    const allowed = new Set(["/index.html", "/app.js", "/styles.css", "/login.html", "/dashboard.html", "/admin.html", "/setup-owner.html"]);
    if (!allowed.has(assetPath)) return new Response("Not Found", { status: 404 });
    const asset = await env.FILES.get("static" + assetPath, "text");
    if (asset === null) return new Response("Not Found", { status: 404 });
    const contentType = assetPath.endsWith(".html") ? "text/html; charset=utf-8" : assetPath.endsWith(".css") ? "text/css; charset=utf-8" : "application/javascript; charset=utf-8";
    const cacheControl = assetPath.endsWith(".html") ? "public, max-age=60, stale-while-revalidate=300" : "public, max-age=3600, stale-while-revalidate=86400";
    return new Response(asset, { headers: { "content-type": contentType, "cache-control": cacheControl, "x-content-type-options": "nosniff" } });
  }
};
