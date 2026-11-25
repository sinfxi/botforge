const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin-when-cross-origin" };
const MAX_UPLOAD = 5 * 1024 * 1024;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();
async function createPublicId(env) {
  for (let attempt = 0; attempt < 40; attempt++) {
    const bytes = new Uint32Array(1);
    crypto.getRandomValues(bytes);
    const publicId = String(1000 + (bytes[0] % 9000));
    const exists = await env.DB.prepare("SELECT 1 FROM users WHERE public_id = ? LIMIT 1").bind(publicId).first();
    if (!exists) return publicId;
  }
  throw new Error("Could not allocate a unique 4-digit public user ID.");
}
async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function passwordHash(password, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100000, hash: "SHA-256" }, material, 256);
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
function normalizeUserId(value) {
  return safeText(value, 16)
    .replace(/[۰-۹]/g, digit => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)))
    .replace(/[٠-٩]/g, digit => String("٠١٢٣٤٥٦٧٨٩".indexOf(digit)))
    .slice(0, 4);
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
    "SELECT users.id, users.public_id, users.username, users.role, users.status, users.permissions_json FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?"
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
function safePermissions(value) { try { const p=JSON.parse(value || "[]"); return Array.isArray(p) ? [...new Set(p.filter(x => ["submissions","users","bots","audit"].includes(x)))] : []; } catch { return []; } }
function sameOrigin(request) {
  const requestUrl = new URL(request.url);
  const origin = request.headers.get("origin");
  if (origin) {
    try { return new URL(origin).origin === requestUrl.origin; } catch { return false; }
  }
  const referer = request.headers.get("referer");
  if (referer) {
    try { return new URL(referer).origin === requestUrl.origin; } catch { return false; }
  }
  return false;
}
async function audit(env, actor, action, targetType = null, targetId = null, details = null) {
  await env.DB.prepare("INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, details_json) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(id(), actor || null, action, targetType, targetId, details ? JSON.stringify(details) : null).run();
}
async function notify(env, userId, title, body, type = "info") {
  await env.DB.prepare("INSERT INTO notifications (id, user_id, title, body, type) VALUES (?, ?, ?, ?, ?)")
    .bind(id(), userId, title, body, type).run();
}

function luckyIdReward(publicId) {
  const d = String(publicId || "");
  if (!/^\d{4}$/.test(d)) return null;
  const digits = [...d].map(Number);
  if (digits.every(x => x === digits[0])) return { pattern: "چهار رقم یکسان", reward: 1000, title: "شناسه افسانه‌ای" };
  const ascending = digits.every((x, i) => i === 0 || x === digits[i - 1] + 1);
  const descending = digits.every((x, i) => i === 0 || x === digits[i - 1] - 1);
  if (ascending || descending) return { pattern: "ترتیب پیوسته", reward: 400, title: "شناسه ترتیبی" };
  if (d[0] === d[3] && d[1] === d[2]) return { pattern: "قرینه", reward: 300, title: "شناسه آینه‌ای" };
  if (d[0] === d[1] && d[2] === d[3]) return { pattern: "دو جفت", reward: 200, title: "شناسه دوتایی" };
  if (d[0] === d[2] && d[1] === d[3]) return { pattern: "الگوی متناوب", reward: 180, title: "شناسه ریتمیک" };
  if ([...d].filter((x, i) => d.indexOf(x) !== i).length >= 2) return { pattern: "سه رقم مشابه", reward: 120, title: "شناسه کمیاب" };
  return null;
}

async function handleApi(request, env, url) {
  if (!env.DB) return json({ error: "Database binding is not configured." }, 503);
  const path = url.pathname;
  const method = request.method;

  if (path === "/api/health" && method === "GET") {
    try {
      await env.DB.prepare("SELECT 1").first();
      return json({ ok: true, service: "FXI BotForge", database: "connected", storage: env.FILES ? "KV configured" : "missing", authentication: "user_id + password", edge: request.cf?.colo || null, checked_at: now() });
    } catch (error) {
      console.error("Health check failed:", error);
      return json({ ok: false, database: "unavailable", error: "اتصال پایگاه داده برقرار نیست." }, 503);
    }
  }

  if (path === "/api/auth/bootstrap/status" && method === "GET") {
    const existing = await env.DB.prepare("SELECT id FROM users WHERE role IN ('owner','admin') LIMIT 1").first();
    return json({ available: !existing });
  }

  if (path === "/api/auth/bootstrap" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const body = await request.json().catch(() => null);
    const publicId = normalizeUserId(body?.user_id);
    const password = typeof body?.password === "string" ? body.password : "";
    if (!/^\d{4}$/.test(publicId) || password.length < 1 || password.length > 200) {
      return json({ error: "شناسه مالک باید دقیقاً ۴ رقم و رمز عبور باید بین ۱ تا ۲۰۰ کاراکتر باشد." }, 400);
    }
    const requestId = id();
    try {
      const salt = id(), userId = id();
      const username = "owner_" + publicId;
      const email = username + "@accounts.botforge.invalid";
      const results = await env.DB.batch([
        env.DB.prepare("INSERT INTO users (id,public_id,email,username,password_hash,password_salt,role) SELECT ?,?,?,?,?,?,'owner' WHERE NOT EXISTS (SELECT 1 FROM users WHERE role IN ('owner','admin'))")
          .bind(userId, publicId, email, username, await passwordHash(password, salt), salt),
        env.DB.prepare("INSERT INTO audit_logs (id,actor_id,action,target_type,target_id,details_json) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=? AND role='owner')")
          .bind(id(), userId, "owner.bootstrap", "user", userId, null, userId)
      ]);
      const inserted = Number(results?.[0]?.meta?.changes ?? results?.[0]?.changes ?? 0);
      if (inserted !== 1) return json({ error: "حساب مالک قبلاً ساخته شده است؛ فقط اولین ثبت‌کننده می‌تواند مالک باشد." }, 409);
      return json({ ok: true, user_id: publicId, message: "حساب مالک ساخته شد. با همین شناسه و رمز وارد شو." }, 201);
    } catch (error) {
      console.error("Owner bootstrap failed:", requestId, error);
      const message = String(error?.message || error);
      if (/UNIQUE constraint failed/i.test(message)) return json({ error: "این شناسه قبلاً استفاده شده یا مالک قبلاً ساخته شده است." }, 409);
      const diagnostic = message.replace(/[\r\n\t]/g, " ").slice(0, 180);
      return json({ error: "ساخت حساب مالک ناموفق بود.", request_id: requestId, diagnostic }, 500);
    }
  }
  if (path === "/api/auth/register" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const body = await request.json().catch(() => null);
    if (!body || typeof body.username !== "string" || typeof body.password !== "string") return json({ error: "نام کاربری و رمز عبور را کامل وارد کن." }, 400);
    const username = body.username.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,24}$/.test(username) || body.password.length < 10 || body.password.length > 200) return json({ error: "نام کاربری باید ۳ تا ۲۴ کاراکتر و شامل حروف انگلیسی، عدد یا _ باشد؛ رمز حداقل ۱۰ کاراکتر باشد." }, 400);
    const salt = id(), userId = id();
    try {
      const publicId = await createPublicId(env);
      await env.DB.prepare("INSERT INTO users (id,public_id,email,username,password_hash,password_salt) VALUES (?,?,?,?,?,?)").bind(userId, publicId, username + "@accounts.botforge.invalid", username, await passwordHash(body.password, salt), salt).run();
      return json({ ok: true, user_id: publicId, username, message: "حساب ساخته شد. شناسه ۴ رقمی را نگه دار و وارد شو." }, 201);
    } catch (error) {
      console.error("Registration failed:", error);
      if (/UNIQUE constraint failed/i.test(String(error?.message || error))) return json({ error: "این نام کاربری قبلاً ثبت شده است." }, 409);
      return json({ error: "ذخیره حساب در پایگاه داده ناموفق بود. اتصال پایگاه داده را بررسی کن." }, 500);
    }
  }
  if (path === "/api/auth/login" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const body = await request.json().catch(() => null);
    if (!body || typeof body.user_id !== "string" || typeof body.password !== "string") return json({ error: "شناسه کاربری و رمز عبور را کامل وارد کن." }, 400);
    const userId = normalizeUserId(body.user_id);
    const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
    if (!/^\d{4}$/.test(userId) || (username && !/^[a-z0-9_]{3,24}$/.test(username)) || body.password.length > 200) return json({ error: "شناسه کاربری باید دقیقاً ۴ رقم باشد." }, 400);
    const user = username
      ? await env.DB.prepare("SELECT id,password_hash,password_salt,status,role FROM users WHERE public_id = ? AND username = ?").bind(userId, username).first()
      : await env.DB.prepare("SELECT id,password_hash,password_salt,status,role FROM users WHERE public_id = ?").bind(userId).first();
    if (!user || user.status !== "active" || await passwordHash(body.password, user.password_salt) !== user.password_hash) return json({ error: "شناسه کاربری، نام کاربری یا رمز عبور اشتباه است." }, 401);
    const token = `${id()}.${id()}`;
    const days = Math.min(30, Math.max(1, Number(env.SESSION_DAYS) || 14));
    await env.DB.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)").bind(id(), user.id, await sha256(token), new Date(Date.now() + days * 86400000).toISOString()).run();
    return json({ ok: true, role: user.role }, 200, { "set-cookie": cookie("fxi_session", token, days * 86400) });
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


  if (path === "/api/community/me" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(auth.user.id).run();
    const [wallet, claim, rewards, purchases, transactions] = await Promise.all([
      env.DB.prepare("SELECT balance FROM ncoin_wallets WHERE user_id=?").bind(auth.user.id).first(),
      env.DB.prepare("SELECT pattern,reward,claimed_at FROM ncoin_lucky_claims WHERE user_id=?").bind(auth.user.id).first(),
      env.DB.prepare("SELECT id,title,description,price FROM ncoin_rewards WHERE active=1 ORDER BY sort_order,price").all(),
      env.DB.prepare("SELECT p.id,p.price,p.status,p.created_at,r.title FROM ncoin_purchases p JOIN ncoin_rewards r ON r.id=p.reward_id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 20").bind(auth.user.id).all(),
      env.DB.prepare("SELECT amount,kind,description,created_at FROM ncoin_transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 12").bind(auth.user.id).all()
    ]);
    return json({ user_id:auth.user.public_id, username:auth.user.username, balance:Number(wallet?.balance||0), lucky:luckyIdReward(auth.user.public_id), claim:claim||null, rewards:rewards.results||[], purchases:purchases.results||[], transactions:transactions.results||[] });
  }

  if (path === "/api/community/search" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const publicId = normalizeUserId(url.searchParams.get("id"));
    if (!/^\d{4}$/.test(publicId)) return json({error:"شناسه باید دقیقاً ۴ رقم باشد."},400);
    const user = await env.DB.prepare("SELECT id,public_id,username,role,created_at FROM users WHERE public_id=? AND status='active'").bind(publicId).first();
    if (!user) return json({error:"کاربری با این شناسه پیدا نشد."},404);
    const projects = await env.DB.prepare("SELECT COUNT(*) AS count FROM bots WHERE uploader_id=? AND status='published'").bind(user.id).first();
    return json({user:{public_id:user.public_id,username:user.username,role:user.role==="user"?"member":user.role,joined_at:user.created_at,projects:Number(projects?.count||0)}});
  }

  if (path === "/api/community/lucky/claim" && method === "POST") {
    if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(auth.user.id).run();
    const lucky = luckyIdReward(auth.user.public_id);
    if (!lucky) return json({ok:false,eligible:false,message:"شناسه‌ات در دسته شناسه‌های رُند جایزه‌دار نیست؛ اما می‌توانی با فعالیت در BotForge سکه جمع کنی."},200);
    const claimId = id();
    const inserted = await env.DB.prepare("INSERT OR IGNORE INTO ncoin_lucky_claims(user_id,pattern,reward) VALUES(?,?,?)").bind(auth.user.id,lucky.pattern,lucky.reward).run();
    const changes = Number(inserted?.meta?.changes ?? inserted?.changes ?? 0);
    if (!changes) return json({ok:true,claimed:false,message:"جایزه شناسه‌ات قبلاً دریافت شده است."});
    await env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=?").bind(lucky.reward,now(),auth.user.id).run();
    await env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) VALUES(?,?,?,?,?)").bind(claimId,auth.user.id,lucky.reward,"lucky_id","جایزه شناسه رُند: "+lucky.title).run();
    await audit(env,auth.user.id,"ncoin.lucky.claim","user",auth.user.id,{pattern:lucky.pattern,reward:lucky.reward});
    return json({ok:true,claimed:true,reward:lucky.reward,pattern:lucky.pattern,balance:(await env.DB.prepare("SELECT balance FROM ncoin_wallets WHERE user_id=?").bind(auth.user.id).first())?.balance||lucky.reward});
  }

  if (path === "/api/community/rewards/purchase" && method === "POST") {
    if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const body = await request.json().catch(()=>null);
    const rewardId = safeText(body?.reward_id,80);
    const reward = await env.DB.prepare("SELECT id,title,price FROM ncoin_rewards WHERE id=? AND active=1").bind(rewardId).first();
    if (!reward) return json({error:"این جایزه در حال حاضر موجود نیست."},404);
    await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(auth.user.id).run();
    const purchaseId=id();
    const update = await env.DB.prepare("UPDATE ncoin_wallets SET balance=balance-?,updated_at=? WHERE user_id=? AND balance>=?").bind(reward.price,now(),auth.user.id,reward.price).run();
    const changed = Number(update?.meta?.changes ?? update?.changes ?? 0);
    if (!changed) return json({error:"موجودی N Coin برای خرید این جایزه کافی نیست."},400);
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO ncoin_purchases(id,user_id,reward_id,price) VALUES(?,?,?,?)").bind(purchaseId,auth.user.id,reward.id,reward.price),
        env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) VALUES(?,?,?,?,?)").bind(id(),auth.user.id,-reward.price,"purchase","خرید: "+reward.title)
      ]);
    } catch (error) {
      await env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=?").bind(reward.price,now(),auth.user.id).run();
      throw error;
    }
    await audit(env,auth.user.id,"ncoin.reward.purchase","reward",reward.id,{purchase_id:purchaseId,price:reward.price});
    return json({ok:true,purchase_id:purchaseId,message:"درخواست خرید ثبت شد؛ مالک آن را بررسی می‌کند."},201);
  }

  if (path === "/api/community/owner-chat" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const {results}=await env.DB.prepare("SELECT id,sender_role,body,read_at,created_at FROM owner_messages WHERE user_id=? ORDER BY created_at ASC LIMIT 100").bind(auth.user.id).all();
    await env.DB.prepare("UPDATE owner_messages SET read_at=? WHERE user_id=? AND sender_role='owner' AND read_at IS NULL").bind(now(),auth.user.id).run();
    return json({items:results||[]});
  }

  if (path === "/api/community/owner-chat" && method === "POST") {
    if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
    const auth=await requireUser(request,env);
    if(auth.response)return auth.response;
    const body=await request.json().catch(()=>null);
    const message=safeText(body?.message,2000);
    if(message.length<1)return json({error:"پیام خالی است."},400);
    const count=await env.DB.prepare("SELECT COUNT(*) AS count FROM owner_messages WHERE user_id=? AND sender_role='user' AND created_at>?").bind(auth.user.id,new Date(Date.now()-60000).toISOString()).first();
    if(Number(count?.count||0)>=5)return json({error:"برای جلوگیری از اسپم، هر دقیقه حداکثر ۵ پیام می‌توانی بفرستی."},429);
    const messageId=id();
    await env.DB.prepare("INSERT INTO owner_messages(id,user_id,sender_role,body) VALUES(?,?,'user',?)").bind(messageId,auth.user.id,message).run();
    return json({ok:true,id:messageId},201);
  }

  if (path === "/api/public/stats" && method === "GET") {
    try {
      const [projects, creators, downloads] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS count FROM bots WHERE status='published'").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE status='active'").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action='bot.download'").first()
      ]);
      return json({ projects:Number(projects?.count || 0), creators:Number(creators?.count || 0), downloads:Number(downloads?.count || 0), updated_at:now() }, 200, { "cache-control":"public, max-age=0, s-maxage=15, stale-while-revalidate=30" });
    } catch (error) {
      console.error("Public stats failed:", error);
      return json({ error:"آمار عمومی موقتاً در دسترس نیست." }, 503);
    }
  }

  if (path === "/api/bots" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT id,slug,title,description,category,original_filename,file_size,published_at FROM bots WHERE status='published' ORDER BY published_at DESC LIMIT 100").all();
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

  if (path === "/api/notifications/read-all" && method === "POST") {
    if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    await env.DB.prepare("UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL").bind(now(), auth.user.id).run();
    return json({ ok: true });
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
    const extension = (bot.original_filename || "").split(".").pop().toLowerCase();
    const mimeTypes = { zip:"application/zip", py:"text/x-python; charset=utf-8", js:"text/javascript; charset=utf-8", mjs:"text/javascript; charset=utf-8", ts:"text/plain; charset=utf-8", html:"text/html; charset=utf-8", css:"text/css; charset=utf-8", json:"application/json; charset=utf-8", md:"text/markdown; charset=utf-8", txt:"text/plain; charset=utf-8", pdf:"application/pdf", png:"image/png", jpg:"image/jpeg", jpeg:"image/jpeg", webp:"image/webp", svg:"image/svg+xml", xml:"application/xml; charset=utf-8", csv:"text/csv; charset=utf-8" };
    const contentType = mimeTypes[extension] || "application/octet-stream";
    return new Response(object, { headers: { "content-type": contentType, "content-disposition": "attachment; filename=\"source.zip\"; filename*=UTF-8''" + encodedName, "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
  }

  if (path.startsWith("/api/admin/")) {
    const admin = await requireAdmin(request, env);
    if (admin.response) return admin.response;
    const managerRoute = path.match(/^\/api\/admin\/managers(?:\/([0-9a-f-]+)\/(permissions|remove))?$/i);
    if (path === "/api/admin/managers" || managerRoute) {
      if (admin.user.role !== "owner") return json({ error: "فقط مالک اصلی می‌تواند مدیران را مدیریت کند." }, 403);
      if (path === "/api/admin/managers" && method === "GET") {
        const { results } = await env.DB.prepare("SELECT id,public_id,username,status,permissions_json,created_at FROM users WHERE role='admin' ORDER BY created_at DESC").all();
        return json({ items: (results || []).map(u => ({...u, permissions: safePermissions(u.permissions_json)})) });
      }
      if (path === "/api/admin/managers" && method === "POST") {
        if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
        const body = await request.json().catch(() => null);
        const username = safeText(body?.username, 24).toLowerCase();
        const password = typeof body?.password === "string" ? body.password : "";
        const allowed = ["submissions","users","bots","audit"];
        const permissions = Array.isArray(body?.permissions) ? [...new Set(body.permissions.filter(p => allowed.includes(p)))] : [];
        if (!/^[a-z0-9_]{3,24}$/.test(username) || password.length < 12 || password.length > 200 || !permissions.length) return json({ error: "نام کاربری معتبر، رمز حداقل ۱۲ کاراکتری و حداقل یک دسترسی لازم است." }, 400);
        const salt = id(), managerId = id();
        let publicId;
        try {
          publicId = await createPublicId(env);
          await env.DB.prepare("INSERT INTO users (id,public_id,email,username,password_hash,password_salt,role,permissions_json) VALUES (?,?,?,?,?,?,?,?)").bind(managerId,publicId,username + "@accounts.botforge.invalid",username,await passwordHash(password,salt),salt,"admin",JSON.stringify(permissions)).run();
        } catch (error) {
          console.error("Manager creation failed:", error);
          if (/UNIQUE constraint failed/i.test(String(error?.message || error))) return json({ error: "این نام کاربری قبلاً در BotForge ثبت شده است." }, 409);
          return json({ error: "ساخت حساب مدیر در پایگاه داده ناموفق بود. دوباره تلاش کن." }, 500);
        }
        await audit(env,admin.user.id,"manager.create","user",managerId,{username,permissions});
        return json({ok:true,id:managerId,public_id:publicId,username},201);
      }
      if (managerRoute && managerRoute[1] && managerRoute[2] === "permissions" && method === "POST") {
        if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
        const target=await env.DB.prepare("SELECT id,username FROM users WHERE id=? AND role='admin'").bind(managerRoute[1]).first();
        if (!target) return json({error:"مدیر پیدا نشد."},404);
        const body=await request.json().catch(()=>null), allowed=["submissions","users","bots","audit"];
        const permissions=Array.isArray(body?.permissions)?[...new Set(body.permissions.filter(p=>allowed.includes(p)))]:[];
        if (!permissions.length) return json({error:"حداقل یک دسترسی انتخاب کن."},400);
        await env.DB.prepare("UPDATE users SET permissions_json=?,updated_at=? WHERE id=? AND role='admin'").bind(JSON.stringify(permissions),now(),target.id).run();
        await audit(env,admin.user.id,"manager.permissions","user",target.id,{permissions});
        return json({ok:true});
      }
      if (managerRoute && managerRoute[1] && managerRoute[2] === "remove" && method === "POST") {
        if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
        const target=await env.DB.prepare("SELECT id,username FROM users WHERE id=? AND role='admin'").bind(managerRoute[1]).first();
        if (!target) return json({error:"مدیر پیدا نشد."},404);
        await env.DB.prepare("UPDATE users SET role='user',permissions_json=NULL,updated_at=? WHERE id=? AND role='admin'").bind(now(),target.id).run();
        await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(target.id).run();
        await audit(env,admin.user.id,"manager.remove","user",target.id,{username:target.username});
        return json({ok:true});
      }
      return json({error:"روش درخواست پشتیبانی نمی‌شود."},405);
    }

    if (path === "/api/admin/owner-chat" && method === "GET") {
      if (admin.user.role !== "owner") return json({error:"فقط مالک اصلی می‌تواند پیام‌های خصوصی را ببیند."},403);
      const {results}=await env.DB.prepare("SELECT u.id AS user_id,u.public_id,u.username,MAX(m.created_at) AS last_message,SUM(CASE WHEN m.sender_role='user' AND m.read_at IS NULL THEN 1 ELSE 0 END) AS unread, (SELECT body FROM owner_messages x WHERE x.user_id=u.id ORDER BY x.created_at DESC LIMIT 1) AS last_body FROM users u JOIN owner_messages m ON m.user_id=u.id GROUP BY u.id ORDER BY last_message DESC LIMIT 100").all();
      return json({items:results||[]});
    }
    const ownerThread=path.match(/^\/api\/admin\/owner-chat\/([0-9a-f-]+)$/i);
    if(ownerThread && method === "GET") {
      if(admin.user.role!=="owner")return json({error:"فقط مالک اصلی دسترسی دارد."},403);
      const {results}=await env.DB.prepare("SELECT id,sender_role,body,read_at,created_at FROM owner_messages WHERE user_id=? ORDER BY created_at ASC LIMIT 200").bind(ownerThread[1]).all();
      await env.DB.prepare("UPDATE owner_messages SET read_at=? WHERE user_id=? AND sender_role='user' AND read_at IS NULL").bind(now(),ownerThread[1]).run();
      return json({items:results||[]});
    }
    if(ownerThread && method === "POST") {
      if(!sameOrigin(request))return json({error:"درخواست نامعتبر است."},403);
      if(admin.user.role!=="owner")return json({error:"فقط مالک اصلی دسترسی دارد."},403);
      const body=await request.json().catch(()=>null), message=safeText(body?.message,2000);
      if(!message)return json({error:"پیام خالی است."},400);
      const target=await env.DB.prepare("SELECT id FROM users WHERE id=? AND status='active'").bind(ownerThread[1]).first();
      if(!target)return json({error:"کاربر پیدا نشد."},404);
      await env.DB.prepare("INSERT INTO owner_messages(id,user_id,sender_role,body) VALUES(?,?,'owner',?)").bind(id(),target.id,message).run();
      await notify(env,target.id,"پاسخ جدید از مالک BotForge","برای مشاهده پاسخ، وارد بخش گفت‌وگو با مالک شو.","info");
      return json({ok:true},201);
    }
    if(path === "/api/admin/ncoin/purchases" && method === "GET") {
      if(admin.user.role!=="owner")return json({error:"فقط مالک اصلی دسترسی دارد."},403);
      const {results}=await env.DB.prepare("SELECT p.id,p.price,p.status,p.created_at,u.public_id,u.username,r.title FROM ncoin_purchases p JOIN users u ON u.id=p.user_id JOIN ncoin_rewards r ON r.id=p.reward_id ORDER BY p.created_at DESC LIMIT 100").all();
      return json({items:results||[]});
    }
    const purchaseStatus=path.match(/^\/api\/admin\/ncoin\/purchases\/([0-9a-f-]+)\/(approve|deliver|reject)$/i);
    if(purchaseStatus && method==="POST") {
      if(!sameOrigin(request))return json({error:"درخواست نامعتبر است."},403);
      if(admin.user.role!=="owner")return json({error:"فقط مالک اصلی دسترسی دارد."},403);
      const purchase=await env.DB.prepare("SELECT id,user_id,price,status FROM ncoin_purchases WHERE id=?").bind(purchaseStatus[1]).first();
      if(!purchase)return json({error:"خرید پیدا نشد."},404);
      const action=purchaseStatus[2].toLowerCase();
      const status=action==="deliver"?"delivered":action==="approve"?"approved":"rejected";
      if(purchase.status==="rejected"||purchase.status==="delivered")return json({error:"این درخواست قبلاً نهایی شده است."},409);
      if(status==="rejected") {
        await env.DB.prepare("UPDATE ncoin_purchases SET status='rejected',updated_at=? WHERE id=?").bind(now(),purchase.id).run();
        await env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=?").bind(purchase.price,now(),purchase.user_id).run();
        await env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) VALUES(?,?,?,?,?)").bind(id(),purchase.user_id,purchase.price,"refund","بازگشت وجه خرید ردشده").run();
      } else {
        await env.DB.prepare("UPDATE ncoin_purchases SET status=?,updated_at=? WHERE id=?").bind(status,now(),purchase.id).run();
      }
      await notify(env,purchase.user_id,"وضعیت سفارش N Coin تغییر کرد",status==="rejected"?"سفارش رد شد و سکه‌ها به کیف پول برگشتند.":status==="approved"?"سفارش تأیید شد و در صف انجام قرار گرفت.":"جایزه خریداری‌شده تحویل شد.","info");
      return json({ok:true,status});
    }

    const capability = path.includes("/submissions") ? "submissions" : path.includes("/users") ? "users" : path.includes("/bots") ? "bots" : path.includes("/audit") ? "audit" : null;
    if (admin.user.role !== "owner" && capability) {
      const permissions = safePermissions(admin.user.permissions_json);
      if (!permissions.includes(capability)) return json({error:"این دسترسی برای حساب مدیر فعال نیست."},403);
    }
    if (path === "/api/admin/overview" && method === "GET") {
      const permissions = admin.user.role === "owner"
        ? ["submissions", "users", "bots", "audit"]
        : safePermissions(admin.user.permissions_json);
      const result = {};
      const jobs = [];
      if (permissions.includes("users")) jobs.push(env.DB.prepare("SELECT COUNT(*) AS count FROM users").first().then(row => { result.users = row.count; }));
      if (permissions.includes("bots")) jobs.push(env.DB.prepare("SELECT COUNT(*) AS count FROM bots WHERE status='published'").first().then(row => { result.bots = row.count; }));
      if (permissions.includes("submissions")) jobs.push(Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS count FROM submissions WHERE status='pending'").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM submissions").first()
      ]).then(([pending, submissions]) => { result.pending = pending.count; result.submissions = submissions.count; }));
      if (permissions.includes("audit")) jobs.push(env.DB.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action='bot.download'").first().then(row => { result.downloads = row.count; }));
      await Promise.all(jobs);
      return json(result);
    }
    if (path === "/api/admin/submissions" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT s.id,s.title,s.description,s.category,s.original_filename,s.file_size,s.status,s.created_at,u.username AS uploader_username FROM submissions s JOIN users u ON u.id=s.user_id ORDER BY CASE s.status WHEN 'pending' THEN 0 ELSE 1 END,s.created_at DESC LIMIT 100").all();
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
      await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(submission.user_id).run();
      await env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+50,updated_at=? WHERE user_id=?").bind(now(),submission.user_id).run();
      await env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) VALUES(?,?,?,?,?)").bind(id(),submission.user_id,50,"project_approved","پاداش انتشار پروژه تأییدشده").run();
      return json({ ok: true, slug });
    }
    if (path === "/api/admin/users" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT id,public_id,username,role,status,created_at FROM users ORDER BY created_at DESC LIMIT 200").all();
      return json({ items: results || [] });
    }
    const userStatus = path.match(/^\/api\/admin\/users\/([0-9a-f-]+)\/(suspend|activate)$/i);
    if (userStatus && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
      if (userStatus[1] === admin.user.id) return json({ error: "نمی‌توانی حساب خودت را غیرفعال کنی." }, 400);
      const target = await env.DB.prepare("SELECT id,username,role FROM users WHERE id=?").bind(userStatus[1]).first();
      if (!target) return json({ error: "کاربر پیدا نشد." }, 404);
      if (target.role === "owner" && admin.user.role !== "owner") return json({ error: "فقط مالک اصلی می‌تواند حساب مالک را تغییر دهد." }, 403);
      if (target.role === "admin" && admin.user.role !== "owner") return json({ error: "مدیران فقط توسط مالک اصلی قابل مدیریت هستند." }, 403);
      const status = userStatus[2].toLowerCase() === "suspend" ? "suspended" : "active";
      await env.DB.prepare("UPDATE users SET status=?,updated_at=? WHERE id=?").bind(status, now(), target.id).run();
      if (status === "suspended") await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(target.id).run();
      await audit(env, admin.user.id, "user." + status, "user", target.id, { username: target.username });
      return json({ ok: true, status });
    }
    if (path === "/api/admin/bots/publish" && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "درخواست نامعتبر است." }, 403);
      if (!env.FILES) return json({ error: "فضای ذخیره‌سازی فایل پیکربندی نشده است." }, 503);
      const form = await request.formData().catch(() => null);
      if (!form) return json({ error: "فرم ارسال‌شده قابل خواندن نیست." }, 400);
      const title = safeText(form.get("title"), 90);
      const description = safeText(form.get("description"), 1200);
      const category = safeText(form.get("category"), 40);
      const kind = String(form.get("kind") || "");
      const rights = form.get("rights") === "on";
      if (title.length < 3 || description.length < 10 || !category || !rights) return json({ error: "نام، توضیحات، دسته‌بندی و تأیید حق انتشار الزامی است." }, 400);
      let bytes, filename;
      if (kind === "code") {
        const code = String(form.get("code") || "");
        filename = safeFilename(String(form.get("code_filename") || ""));
        if (!code.trim() || code.length > 200000 || !/^[a-zA-Z0-9._-]{1,100}$/.test(filename)) return json({ error: "کد یا نام فایل معتبر نیست؛ از نامی مثل main.py استفاده کن." }, 400);
        bytes = new TextEncoder().encode(code);
      } else if (kind === "zip" || kind === "file") {
        const file = form.get("file");
        if (!(file instanceof File) || file.size < 1 || file.size > (Number(env.MAX_UPLOAD_BYTES) || MAX_UPLOAD)) return json({ error: "فایل خالی است یا از سقف ۵ مگابایت بیشتر است." }, 400);
        filename = safeFilename(file.name);
        if (!filename || filename.length > 120) return json({ error: "نام فایل معتبر نیست." }, 400);
        bytes = await file.arrayBuffer();
        if (kind === "zip") {
          if (!filename.toLowerCase().endsWith(".zip")) return json({ error: "برای این حالت فقط فایل ZIP انتخاب کن." }, 400);
          const head = new Uint8Array(bytes.slice(0, 4));
          if (!(head[0] === 0x50 && head[1] === 0x4b && [0x03,0x05,0x07].includes(head[2]) && [0x04,0x06,0x08].includes(head[3]))) return json({ error: "ساختار فایل ZIP معتبر نیست." }, 400);
        }
      } else return json({ error: "نوع انتشار را انتخاب کن." }, 400);
      const botId = id();
      const slug = `${slugify(title)}-${botId.slice(0,8)}`;
      const objectKey = `published/${slug}/${filename}`;
      await env.FILES.put(objectKey, bytes);
      try {
        await env.DB.prepare("INSERT INTO bots (id,slug,title,description,category,object_key,original_filename,file_size,uploader_id) VALUES (?,?,?,?,?,?,?,?,?)")
          .bind(botId, slug, title, description, category, objectKey, filename, bytes.byteLength, admin.user.id).run();
      } catch (error) {
        await env.FILES.delete(objectKey);
        throw error;
      }
      await audit(env, admin.user.id, "bot.publish.direct", "bot", botId, { title, category, kind, filename, file_size: bytes.byteLength });
      return json({ ok: true, id: botId, slug, kind, filename, message: "محتوا مستقیماً منتشر شد." }, 201);
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
      const { results } = await env.DB.prepare("SELECT a.id,a.action,a.target_type,a.target_id,a.details_json,a.created_at,u.username AS actor_username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 100").all();
      return json({ items: results || [] });
    }
    return json({ error: "مسیر مدیریت پیدا نشد." }, 404);
  }

  return json({ error: "مسیر API پیدا نشد." }, 404);
}

const STATIC_ASSET_CACHE = new Map();
let STATIC_KV_COOLDOWN_UNTIL = 0;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await handleApi(request, env, url); }
      catch (error) { const requestId = id(); console.error("API request failed:", requestId, error); return json({ error: "ارتباط با سرویس کامل نشد. وضعیت اتصال را بررسی کن و دوباره تلاش کن.", request_id: requestId }, 500); }
    }
    const assetPath = url.pathname === "/" ? "/index.html" : url.pathname;
    const allowed = new Set(["/index.html", "/app.js", "/styles.css", "/login.html", "/dashboard.html", "/admin.html", "/setup-owner.html", "/community.html", "/owner-inbox.html"]);
    if (!allowed.has(assetPath)) return new Response("Not Found", { status: 404 });
    if (request.method !== "GET" && request.method !== "HEAD") return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET, HEAD" } });

    const cached = STATIC_ASSET_CACHE.get(assetPath);
    let asset = cached && cached.expiresAt > Date.now() ? cached.body : null;
    let source = cached && cached.expiresAt > Date.now() ? cached.source : "";

    // KV is the latest release source, but it must never hold the page open indefinitely.
    // Cache successful reads per isolate and temporarily bypass KV after a slow/failing read.
    if (asset === null && env.FILES && Date.now() >= STATIC_KV_COOLDOWN_UNTIL) {
      try {
        const read = env.FILES.get("static" + assetPath, "text");
        let timeoutId;
        try {
          asset = await Promise.race([
            read,
            new Promise(resolve => { timeoutId = setTimeout(() => resolve(null), 1200); })
          ]);
        } finally {
          if (timeoutId) clearTimeout(timeoutId);
        }
        if (asset !== null) {
          source = "kv";
          STATIC_KV_COOLDOWN_UNTIL = 0;
          STATIC_ASSET_CACHE.set(assetPath, { body: asset, source, expiresAt: Date.now() + 15000 });
        } else {
          STATIC_KV_COOLDOWN_UNTIL = Date.now() + 10000;
        }
      } catch (error) {
        console.error("Static KV read failed:", assetPath, error);
        STATIC_KV_COOLDOWN_UNTIL = Date.now() + 10000;
        asset = null;
      }
    }

    if (asset === null && env.ASSETS?.fetch) {
      try {
        const assetUrl = new URL(request.url);
        assetUrl.pathname = assetPath;
        assetUrl.search = "";
        const assetResponse = await env.ASSETS.fetch(new Request(assetUrl, { method: request.method, headers: request.headers }));
        if (assetResponse.status !== 404) {
          const headers = new Headers(assetResponse.headers);
          headers.set("x-fxi-static-source", "assets");
          headers.set("x-content-type-options", "nosniff");
          return assetResponse.body
            ? new Response(request.method === "HEAD" ? null : assetResponse.body, { status: assetResponse.status, statusText: assetResponse.statusText, headers })
            : assetResponse;
        }
      } catch (error) {
        console.error("Static asset fallback failed:", assetPath, error);
      }
    }

    if (asset !== null) {
      if (STATIC_ASSET_CACHE.size > 12) STATIC_ASSET_CACHE.clear();
      const contentType = assetPath.endsWith(".html") ? "text/html; charset=utf-8" : assetPath.endsWith(".css") ? "text/css; charset=utf-8" : "application/javascript; charset=utf-8";
      const cacheControl = assetPath.endsWith(".html") ? "no-store" : "public, max-age=300, stale-while-revalidate=3600";
      return new Response(request.method === "HEAD" ? null : asset, { headers: { "content-type": contentType, "cache-control": cacheControl, "x-fxi-static-source": source || "memory", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=(), microphone=(), geolocation=()" } });
    }
    return new Response("Static asset temporarily unavailable", { status: 503, headers: { "cache-control": "no-store", "retry-after": "5", "content-type": "text/plain; charset=utf-8" } });
  }
};
