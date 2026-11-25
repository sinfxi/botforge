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
    .replace(/[٠-٩]/g, digit => String("٠١٢٣٤٥٦٧٨٩".indexOf(digit)));
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
function safePermissions(value) { try { const p=JSON.parse(value || "[]"); return Array.isArray(p) ? [...new Set(p.filter(x => ["submissions","users","bots","audit","gifts","announcements"].includes(x)))] : []; } catch { return []; } }
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
async function telegramSend(env, chatId, textValue, replyMarkup = undefined) {
  if (!env.TELEGRAM_BOT_TOKEN || !chatId) return false;
  try {
    const payload = { chat_id: chatId, text: String(textValue || "").slice(0, 4000), disable_web_page_preview: true };
    if (replyMarkup) payload.reply_markup = replyMarkup;
    const response = await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/sendMessage", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload)
    });
    return response.ok;
  } catch (error) { console.error("Telegram send failed:", error); return false; }
}
async function notify(env, userId, title, body, type = "info") {
  await env.DB.prepare("INSERT INTO notifications (id, user_id, title, body, type) VALUES (?, ?, ?, ?, ?)")
    .bind(id(), userId, title, body, type).run();
  const link = await env.DB.prepare("SELECT chat_id FROM telegram_links WHERE user_id=?").bind(userId).first();
  if (link?.chat_id) await telegramSend(env, link.chat_id, "🔔 " + title + "\n\n" + body);
}
async function handleTelegramWebhook(request, env) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_WEBHOOK_SECRET) return json({error:"Telegram integration is not configured."},503);
  if (request.headers.get("x-telegram-bot-api-secret-token") !== env.TELEGRAM_WEBHOOK_SECRET) return json({error:"Unauthorized"},401);
  const update = await request.json().catch(() => null);
  const message = update?.message, chatId = message?.chat?.id, chatType = message?.chat?.type || "", from = message?.from;
  const textValue = typeof message?.text === "string" ? message.text.trim() : typeof message?.caption === "string" ? message.caption.trim() : "";
  if (!chatId || !from || (!textValue && !message?.document)) return json({ok:true});
  const parts = textValue.split(/\s+/, 2), commandName = (parts[0] || "").toLowerCase().split("@")[0];

  if (commandName === "/connect") {
    // Native self-service workspace for linked BotForge accounts.
  if (chatType === "private") {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS telegram_bot_states (telegram_user_id TEXT PRIMARY KEY, state TEXT NOT NULL, payload_json TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
    const linkedAccount = await env.DB.prepare("SELECT u.id,u.public_id,u.username,u.role,u.status FROM telegram_links l JOIN users u ON u.id=l.user_id WHERE l.telegram_user_id=? LIMIT 1").bind(String(from.id)).first();
    const menuKeyboard = {
      keyboard: [
        [{text:"👤 حساب من"},{text:"💰 کیف پول"}],
        [{text:"📦 پروژه‌های من"},{text:"📨 درخواست‌های من"}],
        [{text:"🛍 فروشگاه جوایز"},{text:"🎁 ثبت کد هدیه"}],
        [{text:"🔔 اعلان‌ها"},{text:"💬 پشتیبانی"}],
        [{text:"📣 اطلاعیه‌ها"},{text:"🛠 مدیریت"}],
        [{text:"🔗 قطع اتصال تلگرام"}],
        [{text:"❔ راهنما"}]
      ], resize_keyboard:true, is_persistent:true
    };
    const sendHome = async () => {
      if (!linkedAccount || linkedAccount.status !== "active") {
        await telegramSend(env,chatId,"برای استفاده از امکانات حساب، ابتدا حساب سایتت را متصل کن:\n/connect 1234\n\nبعد درخواست اتصال را از داخل همان حساب در سایت تأیید کن.");
        return;
      }
      await env.DB.prepare("DELETE FROM telegram_bot_states WHERE telegram_user_id=?").bind(String(from.id)).run();
      await telegramSend(env,chatId,"سلام "+safeText(from.first_name || linkedAccount.username,40)+" 👋\nبه فضای کاربری FXI BotForge خوش اومدی.\n\nاز دکمه‌های زیر برای مدیریت حساب، پروژه‌ها، کیف پول و پشتیبانی استفاده کن.",menuKeyboard);
    };
    const setState = async (state,payload=null) => env.DB.prepare("INSERT INTO telegram_bot_states(telegram_user_id,state,payload_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(telegram_user_id) DO UPDATE SET state=excluded.state,payload_json=excluded.payload_json,updated_at=excluded.updated_at")
      .bind(String(from.id),state,payload?JSON.stringify(payload):null,now()).run();
    const clearState = async () => env.DB.prepare("DELETE FROM telegram_bot_states WHERE telegram_user_id=?").bind(String(from.id)).run();
    await env.DB.prepare("DELETE FROM telegram_bot_states WHERE telegram_user_id=? AND updated_at<?").bind(String(from.id),new Date(Date.now()-30*60*1000).toISOString()).run();
    const stateRow = await env.DB.prepare("SELECT state,payload_json FROM telegram_bot_states WHERE telegram_user_id=?").bind(String(from.id)).first();
    const state = stateRow?.state || "";
    let statePayload = {};
    try { statePayload = JSON.parse(stateRow?.payload_json || "{}"); } catch {}
    const userAction = textValue;
    if (commandName === "/menu" || commandName === "/account" || userAction === "🏠 منوی اصلی") { await sendHome(); return json({ok:true}); }
    if (commandName === "/projects" || commandName === "/wallet" || commandName === "/rewards" || commandName === "/gift" || commandName === "/notifications" || commandName === "/support") {
      if (!linkedAccount) { await sendHome(); return json({ok:true}); }
    }
    if (linkedAccount && linkedAccount.status === "active") {
      if (state && ["لغو","انصراف"].includes(userAction)) { await clearState(); await telegramSend(env,chatId,"عملیات لغو شد.",menuKeyboard); return json({ok:true}); }
      if (commandName === "/submit" || userAction === "📤 ارسال پروژه") {
        await setState("submission_title");
        await telegramSend(env,chatId,"📤 ثبت پروژه جدید\n\nابتدا عنوان پروژه را بفرست (۳ تا ۱۰۰ کاراکتر). برای انصراف «لغو» را بفرست.",menuKeyboard);
        return json({ok:true});
      }
      if (state === "submission_title") {
        const title = safeText(userAction,100);
        if (title.length < 3) { await telegramSend(env,chatId,"عنوان باید حداقل ۳ کاراکتر باشد. دوباره بفرست."); return json({ok:true}); }
        await setState("submission_description",{title});
        await telegramSend(env,chatId,"حالا توضیحات پروژه را بفرست (حداقل ۱۰ و حداکثر ۲۰۰۰ کاراکتر).");
        return json({ok:true});
      }
      if (state === "submission_description") {
        const description = safeText(userAction,2000);
        if (description.length < 10) { await telegramSend(env,chatId,"توضیحات باید حداقل ۱۰ کاراکتر باشد. دوباره بفرست."); return json({ok:true}); }
        await setState("submission_category",{title:statePayload.title,description});
        await telegramSend(env,chatId,"دسته‌بندی پروژه را بفرست؛ مثلاً Python، ربات تلگرام، ابزار یا وب‌سایت.");
        return json({ok:true});
      }
      if (state === "submission_category") {
        const category = safeText(userAction,50);
        if (category.length < 2) { await telegramSend(env,chatId,"دسته‌بندی معتبر نیست؛ دوباره بفرست."); return json({ok:true}); }
        await setState("submission_rights",{title:statePayload.title,description:statePayload.description,category});
        await telegramSend(env,chatId,"قبل از ارسال فایل تأیید کن که حق انتشار این محتوا را داری و فایل حاوی بدافزار یا محتوای غیرمجاز نیست.\nبرای تأیید دقیقاً بنویس: «تأیید می‌کنم»");
        return json({ok:true});
      }
      if (state === "submission_rights") {
        if (userAction !== "تأیید می‌کنم") { await telegramSend(env,chatId,"برای ادامه باید دقیقاً «تأیید می‌کنم» را بفرستی؛ برای انصراف «لغو»."); return json({ok:true}); }
        await setState("submission_file",statePayload);
        await telegramSend(env,chatId,"حالا فایل ZIP پروژه را به‌صورت Document بفرست. حداکثر حجم ۵ مگابایت است.");
        return json({ok:true});
      }
      if (state === "submission_file") {
        const document = message?.document;
        if (!document) { await telegramSend(env,chatId,"منتظر فایل ZIP هستم. فایل را به‌صورت Document بفرست؛ حداکثر ۵ مگابایت."); return json({ok:true}); }
        const filename = safeFilename(document.file_name || "source.zip");
        const fileSize = Number(document.file_size || 0);
        if (!filename.toLowerCase().endsWith(".zip") || fileSize < 4 || fileSize > (Number(env.MAX_UPLOAD_BYTES)||MAX_UPLOAD)) {
          await telegramSend(env,chatId,"فقط فایل ZIP با حجم حداکثر ۵ مگابایت پذیرفته می‌شود. فایل دیگری بفرست یا «لغو» کن.");
          return json({ok:true});
        }
        const fileInfo = await fetch("https://api.telegram.org/bot"+env.TELEGRAM_BOT_TOKEN+"/getFile?file_id="+encodeURIComponent(document.file_id)).then(r=>r.json()).catch(()=>null);
        if (!fileInfo?.ok || !fileInfo.result?.file_path) { await telegramSend(env,chatId,"دریافت فایل از تلگرام ناموفق بود؛ دوباره ارسالش کن."); return json({ok:true}); }
        const fileResponse = await fetch("https://api.telegram.org/file/bot"+env.TELEGRAM_BOT_TOKEN+"/"+fileInfo.result.file_path);
        if (!fileResponse.ok) { await telegramSend(env,chatId,"دانلود فایل از تلگرام ناموفق بود؛ دوباره تلاش کن."); return json({ok:true}); }
        const bytes = await fileResponse.arrayBuffer();
        if (bytes.byteLength < 4 || bytes.byteLength > (Number(env.MAX_UPLOAD_BYTES)||MAX_UPLOAD)) { await telegramSend(env,chatId,"حجم فایل معتبر نیست یا از ۵ مگابایت بیشتر است."); return json({ok:true}); }
        const head = new Uint8Array(bytes.slice(0,4));
        if (!(head[0]===0x50 && head[1]===0x4b && [0x03,0x05,0x07].includes(head[2]) && [0x04,0x06,0x08].includes(head[3]))) { await telegramSend(env,chatId,"ساختار ZIP معتبر نیست. لطفاً فایل ZIP سالم بفرست."); return json({ok:true}); }
        if (!env.FILES) { await telegramSend(env,chatId,"فضای ذخیره‌سازی فایل موقتاً در دسترس نیست."); return json({ok:true}); }
        const submissionId = id(), objectKey = "pending/"+linkedAccount.id+"/"+submissionId+".zip";
        await env.FILES.put(objectKey,bytes);
        try {
          await env.DB.prepare("INSERT INTO submissions(id,user_id,title,description,category,object_key,original_filename,file_size,rights_confirmed) VALUES(?,?,?,?,?,?,?,?,1)")
            .bind(submissionId,linkedAccount.id,statePayload.title,statePayload.description,statePayload.category,objectKey,filename,bytes.byteLength).run();
        } catch(error) {
          await env.FILES.delete(objectKey);
          throw error;
        }
        await clearState();
        await audit(env,linkedAccount.id,"submission.create.telegram","submission",submissionId,{filename,file_size:bytes.byteLength});
        await telegramSend(env,chatId,"✅ پروژه با موفقیت برای بررسی ارسال شد.\nعنوان: "+safeText(statePayload.title,100)+"\nکد پیگیری: "+submissionId+"\nپس از بررسی، نتیجه را همین‌جا دریافت می‌کنی.",menuKeyboard);
        return json({ok:true});
      }
      if (state === "gift_code" && !textValue.startsWith("/")) {
        const code = safeText(textValue,32).toUpperCase().replace(/[^A-Z0-9]/g,"");
        await clearState();
        if (code.length !== 12) { await telegramSend(env,chatId,"کد باید ۱۲ کاراکتر باشد. دوباره از «🎁 ثبت کد هدیه» شروع کن.",menuKeyboard); return json({ok:true}); }
        await env.DB.prepare("CREATE TABLE IF NOT EXISTS gift_codes (id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL, amount INTEGER NOT NULL, max_uses INTEGER NOT NULL, used_count INTEGER NOT NULL DEFAULT 0, expires_at TEXT, active INTEGER NOT NULL DEFAULT 1, created_by TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
        await env.DB.prepare("CREATE TABLE IF NOT EXISTS gift_redemptions (id TEXT PRIMARY KEY, gift_id TEXT NOT NULL, user_id TEXT NOT NULL, amount INTEGER NOT NULL, redeemed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(gift_id,user_id))").run();
        const gift = await env.DB.prepare("SELECT * FROM gift_codes WHERE code_hash=? AND active=1").bind(await sha256(code.match(/.{1,4}/g).join("-"))).first();
        if (!gift || gift.used_count >= gift.max_uses || (gift.expires_at && gift.expires_at <= now())) { await telegramSend(env,chatId,"این کد نامعتبر، منقضی یا تمام‌شده است.",menuKeyboard); return json({ok:true}); }
        try {
          const result = await env.DB.batch([
            env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(linkedAccount.id),
            env.DB.prepare("UPDATE gift_codes SET used_count=used_count+1 WHERE id=? AND active=1 AND used_count<max_uses AND (expires_at IS NULL OR expires_at>?)").bind(gift.id,now()),
            env.DB.prepare("INSERT INTO gift_redemptions(id,gift_id,user_id,amount) SELECT ?,?,?,? WHERE changes()=1").bind(id(),gift.id,linkedAccount.id,gift.amount),
            env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=? AND changes()=1").bind(gift.amount,now(),linkedAccount.id),
            env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) SELECT ?,?,?,?,? WHERE changes()=1").bind(id(),linkedAccount.id,gift.amount,"gift","دریافت کد هدیه از ربات تلگرام")
          ]);
          const used = Number(result?.[1]?.meta?.changes ?? result?.[1]?.changes ?? 0);
          const inserted = Number(result?.[2]?.meta?.changes ?? result?.[2]?.changes ?? 0);
          if (!used || !inserted) { await telegramSend(env,chatId,"ظرفیت این کد تمام شده یا دیگر فعال نیست.",menuKeyboard); return json({ok:true}); }
          await telegramSend(env,chatId,"🎉 کد هدیه ثبت شد!\n"+gift.amount.toLocaleString("en-US")+" N Coin به کیف پولت اضافه شد.",menuKeyboard);
        } catch (error) {
          if (/UNIQUE constraint failed/i.test(String(error?.message||error))) await telegramSend(env,chatId,"این کد را قبلاً در حساب خودت استفاده کرده‌ای.",menuKeyboard);
          else throw error;
        }
        return json({ok:true});
      }
      if (state === "support_message" && !textValue.startsWith("/")) {
        const message = safeText(textValue,2000);
        if (!message) { await telegramSend(env,chatId,"پیام خالی است؛ متن پیام را بفرست.",menuKeyboard); return json({ok:true}); }
        const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM owner_messages WHERE user_id=? AND sender_role='user' AND created_at>?").bind(linkedAccount.id,new Date(Date.now()-60000).toISOString()).first();
        if (Number(recent?.n||0) >= 5) { await clearState(); await telegramSend(env,chatId,"برای جلوگیری از اسپم، هر دقیقه حداکثر ۵ پیام می‌توانی بفرستی. کمی بعد دوباره تلاش کن.",menuKeyboard); return json({ok:true}); }
        await env.DB.prepare("INSERT INTO owner_messages(id,user_id,sender_role,body) VALUES(?,?,'user',?)").bind(id(),linkedAccount.id,message).run();
        await clearState();
        await telegramSend(env,chatId,"✅ پیامت برای پشتیبانی ارسال شد. پاسخ در همین گفت‌وگو و بخش پشتیبانی سایت نمایش داده می‌شود.",menuKeyboard);
        return json({ok:true});
      }
      if (state === "buy_reward" && !textValue.startsWith("/")) {
        const rewardId = safeText(textValue,80);
        const reward = await env.DB.prepare("SELECT id,title,price FROM ncoin_rewards WHERE id=? AND active=1").bind(rewardId).first();
        if (!reward) { await telegramSend(env,chatId,"شناسه جایزه پیدا نشد. شناسه را دقیقاً از فهرست فروشگاه کپی کن یا «لغو» را بفرست.",menuKeyboard); return json({ok:true}); }
        await setState("confirm_buy",{reward_id:reward.id,title:reward.title,price:reward.price});
        await telegramSend(env,chatId,"🛒 تأیید خرید\n\n"+reward.title+"\nهزینه: "+Number(reward.price).toLocaleString("en-US")+" N Coin\n\nبرای نهایی‌کردن بنویس «تأیید خرید»؛ برای انصراف «لغو».",menuKeyboard);
        return json({ok:true});
      }
      if (state === "confirm_buy" && !textValue.startsWith("/")) {
        if (["لغو","انصراف"].includes(textValue)) { await clearState(); await telegramSend(env,chatId,"خرید لغو شد.",menuKeyboard); return json({ok:true}); }
        if (textValue !== "تأیید خرید") { await telegramSend(env,chatId,"برای ادامه «تأیید خرید» یا برای انصراف «لغو» را بفرست.",menuKeyboard); return json({ok:true}); }
        const reward = await env.DB.prepare("SELECT id,title,price FROM ncoin_rewards WHERE id=? AND active=1").bind(statePayload.reward_id).first();
        await clearState();
        if (!reward) { await telegramSend(env,chatId,"این جایزه دیگر در دسترس نیست.",menuKeyboard); return json({ok:true}); }
        const instant = {
          "profile-badge":{key:"profile_badge",days:null},"profile-frame":{key:"profile_frame",days:null},"profile-theme":{key:"profile_theme",days:null},
          "creator-spotlight":{key:"creator_spotlight",days:7},"creator-spotlight-plus":{key:"creator_spotlight_plus",days:14},
          "featured-project":{key:"featured_project",days:1,project:true},"project-feature-24h":{key:"featured_project",days:1,project:true},
          "project-feature-7d":{key:"featured_project",days:7,project:true},"project-promotion-month":{key:"featured_project",days:30,project:true}
        }[reward.id] || null;
        let project = null;
        if (instant?.project) {
          project = await env.DB.prepare("SELECT id,title,featured_until FROM bots WHERE uploader_id=? AND status='published' ORDER BY published_at DESC LIMIT 1").bind(linkedAccount.id).first();
          if (!project) { await telegramSend(env,chatId,"برای فعال‌سازی این جایزه، ابتدا باید حداقل یک پروژه منتشرشده داشته باشی.",menuKeyboard); return json({ok:true}); }
        }
        if (instant && !instant.days) {
          const already = await env.DB.prepare("SELECT id FROM ncoin_entitlements WHERE user_id=? AND entitlement_key=? AND status='active' AND expires_at IS NULL LIMIT 1").bind(linkedAccount.id,instant.key).first();
          if (already) { await telegramSend(env,chatId,"این مزیت دائمی را قبلاً فعال کرده‌ای.",menuKeyboard); return json({ok:true}); }
        }
        const purchasedAt = now(), purchaseId = id();
        const base = project?.featured_until && project.featured_until > purchasedAt ? Date.parse(project.featured_until) : Date.now();
        const expiresAt = instant?.days ? new Date((Number.isFinite(base)?base:Date.now())+instant.days*86400000).toISOString() : null;
        await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(linkedAccount.id).run();
        const statements = [
          env.DB.prepare("UPDATE ncoin_wallets SET balance=balance-?,updated_at=? WHERE user_id=? AND balance>=?").bind(reward.price,purchasedAt,linkedAccount.id,reward.price),
          env.DB.prepare("INSERT INTO ncoin_purchases(id,user_id,reward_id,price,status) SELECT ?,?,?,?,? WHERE changes()=1").bind(purchaseId,linkedAccount.id,reward.id,reward.price,instant?"delivered":"pending"),
          env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) SELECT ?,?,?,?,? WHERE changes()=1").bind(id(),linkedAccount.id,-reward.price,"purchase","خرید از ربات تلگرام: "+reward.title),
        ];
        if (instant) statements.push(env.DB.prepare("INSERT INTO ncoin_entitlements(id,user_id,reward_id,entitlement_key,activated_at,expires_at,status,metadata_json) SELECT ?,?,?,?,?,?,'active',? WHERE changes()=1").bind(id(),linkedAccount.id,reward.id,instant.key,purchasedAt,expiresAt,project?JSON.stringify({project_id:project.id,project_title:project.title}):null));
        if (project) statements.push(env.DB.prepare("UPDATE bots SET featured_until=? WHERE id=? AND uploader_id=? AND changes()=1").bind(expiresAt,project.id,linkedAccount.id));
        const result = await env.DB.batch(statements);
        const bought = Number(result?.[1]?.meta?.changes ?? result?.[1]?.changes ?? 0);
        if (!bought) { await telegramSend(env,chatId,"موجودی N Coin برای این خرید کافی نیست.",menuKeyboard); return json({ok:true}); }
        await audit(env,linkedAccount.id,"ncoin.reward.purchase.telegram","reward",reward.id,{purchase_id:purchaseId,price:reward.price,instant:!!instant});
        if (instant) await notify(env,linkedAccount.id,"جایزه شما فعال شد ✨","«"+reward.title+"» از طریق ربات فعال شد.","success");
        const balance = await env.DB.prepare("SELECT balance FROM ncoin_wallets WHERE user_id=?").bind(linkedAccount.id).first();
        await telegramSend(env,chatId,(instant?"✨ جایزه با موفقیت فعال شد!":"✅ سفارش ثبت شد و در صف انجام قرار گرفت.")+"\n"+reward.title+"\nموجودی فعلی: "+Number(balance?.balance||0).toLocaleString("en-US")+" N Coin",menuKeyboard);
        return json({ok:true});
      }
      if (["لغو","انصراف"].includes(userAction) && state) { await clearState(); await telegramSend(env,chatId,"عملیات لغو شد.",menuKeyboard); return json({ok:true}); }
      if (commandName === "/account" || userAction === "👤 حساب من") {
        const wallet = await env.DB.prepare("SELECT balance FROM ncoin_wallets WHERE user_id=?").bind(linkedAccount.id).first();
        const [projects,submissions] = await Promise.all([
          env.DB.prepare("SELECT COUNT(*) AS n FROM bots WHERE uploader_id=? AND status='published'").bind(linkedAccount.id).first(),
          env.DB.prepare("SELECT COUNT(*) AS n FROM submissions WHERE user_id=?").bind(linkedAccount.id).first()
        ]);
        await telegramSend(env,chatId,"👤 حساب کاربری\n\nشناسه: "+linkedAccount.public_id+"\nنام کاربری: @"+linkedAccount.username+"\nوضعیت: فعال\nپروژه‌های منتشرشده: "+Number(projects?.n||0)+"\nدرخواست‌های ثبت‌شده: "+Number(submissions?.n||0)+"\nموجودی: "+Number(wallet?.balance||0).toLocaleString("en-US")+" N Coin",menuKeyboard);
        return json({ok:true});
      }
      if (commandName === "/wallet" || userAction === "💰 کیف پول") {
        const wallet = await env.DB.prepare("SELECT balance FROM ncoin_wallets WHERE user_id=?").bind(linkedAccount.id).first();
        const tx = await env.DB.prepare("SELECT amount,description,created_at FROM ncoin_transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 5").bind(linkedAccount.id).all();
        const rows = (tx.results||[]).map(x=>(Number(x.amount)>0?"+":"")+Number(x.amount)+" | "+safeText(x.description,90)).join("\n");
        const lucky = luckyIdReward(linkedAccount.public_id);
        await telegramSend(env,chatId,"💰 کیف پول N Coin\n\nموجودی: "+Number(wallet?.balance||0).toLocaleString("en-US")+" N Coin\n\nآخرین تراکنش‌ها:\n"+(rows||"هنوز تراکنشی ثبت نشده.")+(lucky?"\n\n🎉 شناسه‌ات واجد جایزه "+lucky.reward+" N Coin است. برای دریافت «🎯 دریافت جایزه شناسه» را بزن.":""),{keyboard:[[{text:"🎯 دریافت جایزه شناسه"},{text:"🛍 فروشگاه جوایز"}],[{text:"🏠 منوی اصلی"}]],resize_keyboard:true});
        return json({ok:true});
      }
      if (userAction === "🎯 دریافت جایزه شناسه") {
        const lucky = luckyIdReward(linkedAccount.public_id);
        if (!lucky) { await telegramSend(env,chatId,"شناسه‌ات در حال حاضر مشمول جایزه شناسه رُند نیست.",menuKeyboard); return json({ok:true}); }
        const claim = await env.DB.batch([
          env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(linkedAccount.id),
          env.DB.prepare("INSERT OR IGNORE INTO ncoin_lucky_claims(user_id,pattern,reward) VALUES(?,?,?)").bind(linkedAccount.id,lucky.pattern,lucky.reward),
          env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=? AND changes()=1").bind(lucky.reward,now(),linkedAccount.id),
          env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) SELECT ?,?,?,?,? WHERE changes()=1").bind(id(),linkedAccount.id,lucky.reward,"lucky_id","جایزه شناسه رُند از ربات تلگرام")
        ]);
        const changed = Number(claim?.[1]?.meta?.changes ?? claim?.[1]?.changes ?? 0);
        if (!changed) { await telegramSend(env,chatId,"جایزه شناسه را قبلاً دریافت کرده‌ای.",menuKeyboard); return json({ok:true}); }
        await telegramSend(env,chatId,"🎉 تبریک! "+lucky.reward+" N Coin به کیف پولت اضافه شد.",menuKeyboard);
        return json({ok:true});
      }
      if (commandName === "/projects" || userAction === "📦 پروژه‌های من") {
        const {results=[]}=await env.DB.prepare("SELECT title,category,slug,published_at FROM bots WHERE uploader_id=? AND status='published' ORDER BY published_at DESC LIMIT 10").bind(linkedAccount.id).all();
        await telegramSend(env,chatId,"📦 پروژه‌های منتشرشده تو\n\n"+(results.map((x,i)=>(i+1)+". "+safeText(x.title,90)+"\nدسته: "+safeText(x.category,40)+"\nشناسه: "+x.slug).join("\n\n")||"هنوز پروژه منتشرشده‌ای نداری."),menuKeyboard);
        return json({ok:true});
      }
      if (userAction === "📨 درخواست‌های من") {
        const {results=[]}=await env.DB.prepare("SELECT title,category,status,review_note,created_at FROM submissions WHERE user_id=? ORDER BY created_at DESC LIMIT 10").bind(linkedAccount.id).all();
        const statusLabel = x=>({pending:"در انتظار بررسی",approved:"تأیید و منتشر شد",rejected:"رد شده"})[x]||x;
        await telegramSend(env,chatId,"📨 درخواست‌های من\n\n"+(results.map((x,i)=>(i+1)+". "+safeText(x.title,90)+"\n"+safeText(x.category,40)+" | "+statusLabel(x.status)+(x.review_note?"\nیادداشت: "+safeText(x.review_note,180):"")).join("\n\n")||"هنوز درخواستی ثبت نکرده‌ای.")+"\n\nبرای ارسال فایل ZIP جدید از داشبورد سایت استفاده کن.",menuKeyboard);
        return json({ok:true});
      }
      if (commandName === "/rewards" || userAction === "🛍 فروشگاه جوایز") {
        const {results=[]}=await env.DB.prepare("SELECT id,title,description,price FROM ncoin_rewards WHERE active=1 ORDER BY sort_order,price LIMIT 22").all();
        await setState("buy_reward");
        await telegramSend(env,chatId,"🛍 فروشگاه N Coin\n\n"+results.map(x=>"• "+safeText(x.title,70)+" — "+Number(x.price).toLocaleString("en-US")+" N\nشناسه: "+x.id).join("\n\n")+"\n\nبرای انتخاب، شناسه جایزه را بفرست. قبل از کسر سکه، تأیید نهایی می‌گیری. برای خروج «لغو» را بفرست.",menuKeyboard);
        return json({ok:true});
      }
      if (commandName === "/gift" || userAction === "🎁 ثبت کد هدیه") {
        await setState("gift_code");
        await telegramSend(env,chatId,"🎁 کد هدیه ۱۲ کاراکتری را بفرست. خط تیره مهم نیست. برای انصراف «لغو» را بفرست.",menuKeyboard);
        return json({ok:true});
      }
      if (commandName === "/notifications" || userAction === "🔔 اعلان‌ها") {
        const {results=[]}=await env.DB.prepare("SELECT id,title,body,type,read_at,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 8").bind(linkedAccount.id).all();
        const unread = results.filter(x=>!x.read_at).length;
        await env.DB.prepare("UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL").bind(now(),linkedAccount.id).run();
        await telegramSend(env,chatId,"🔔 اعلان‌های اخیر"+(unread?" ("+unread+" خوانده‌نشده)":"")+"\n\n"+(results.map((x,i)=>(i+1)+". "+safeText(x.title,90)+"\n"+safeText(x.body,240)).join("\n\n")||"اعلانی وجود ندارد."),menuKeyboard);
        return json({ok:true});
      }
      if (commandName === "/support" || userAction === "💬 پشتیبانی") {
        const {results=[]}=await env.DB.prepare("SELECT sender_role,body,created_at FROM owner_messages WHERE user_id=? ORDER BY created_at DESC LIMIT 6").bind(linkedAccount.id).all();
        await setState("support_message");
        await telegramSend(env,chatId,"💬 گفت‌وگو با پشتیبانی\n\n"+(results.reverse().map(x=>(x.sender_role==="user"?"شما":"پشتیبانی")+": "+safeText(x.body,220)).join("\n\n")||"هنوز گفت‌وگویی ثبت نشده.")+"\n\nپیام جدیدت را در یک پیام بفرست. برای انصراف «لغو» را بفرست.",menuKeyboard);
        return json({ok:true});
      }
      if (userAction === "📣 اطلاعیه‌ها") {
        const {results=[]}=await env.DB.prepare("SELECT title,body,kind,gift_code,gift_amount,created_at FROM announcements WHERE active=1 AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at DESC LIMIT 5").bind(now()).all();
        await telegramSend(env,chatId,"📣 اطلاعیه‌های BotForge\n\n"+(results.map(x=>"• "+safeText(x.title,90)+"\n"+safeText(x.body,300)+(x.kind==="gift"&&x.gift_code?"\nکد هدیه: "+x.gift_code+" ("+Number(x.gift_amount||0)+" N Coin)":"")).join("\n\n")||"اطلاعیه فعالی وجود ندارد."),menuKeyboard);
        return json({ok:true});
      }
      if (userAction === "🛠 مدیریت" || commandName === "/admin" || commandName === "/panel") {
        // Continue to the existing permission-checked manager interface below.
      } else if (userAction === "❔ راهنما" || commandName === "/help") {
        await telegramSend(env,chatId,"راهنمای FXI BotForge\n/menu — منوی اصلی\n/account — اطلاعات حساب\n/projects — پروژه‌های منتشرشده تو\n/wallet — کیف پول N Coin\n/rewards — فروشگاه جوایز\n/gift — ثبت کد هدیه\n/notifications — اعلان‌ها\n/support — پشتیبانی\n/submit — ارسال پروژه ZIP
/admin — امکانات مدیریتی (در صورت داشتن دسترسی)",menuKeyboard);
        return json({ok:true});
      } else if (userAction === "🔗 قطع اتصال تلگرام") {
        await setState("confirm_unlink");
        await telegramSend(env,chatId,"برای قطع اتصال، «تأیید قطع اتصال» را بفرست. برای لغو «لغو».",menuKeyboard);
        return json({ok:true});
      } else if (state === "confirm_unlink" && userAction === "تأیید قطع اتصال") {
        await env.DB.prepare("DELETE FROM telegram_links WHERE user_id=?").bind(linkedAccount.id).run();
        await clearState();
        await telegramSend(env,chatId,"اتصال تلگرام قطع شد. برای اتصال دوباره از داخل سایت اقدام کن.");
        return json({ok:true});
      }
    }
  }

  if (chatType !== "private") {
      await telegramSend(env, chatId, "برای اتصال حساب، گفت‌وگوی خصوصی ربات را باز کن و دستور /connect 1234 را بفرست.");
      return json({ok:true});
    }
    const publicId = normalizeUserId(parts[1] || "");
    if (!/^\d{4}$/.test(publicId)) {
      await telegramSend(env, chatId, "شناسه ۴ رقمی حساب سایتت را وارد کن. نمونه: /connect 1234");
      return json({ok:true});
    }
    const target = await env.DB.prepare("SELECT id,public_id FROM users WHERE public_id=? AND status='active'").bind(publicId).first();
    if (!target) {
      await telegramSend(env, chatId, "حسابی با این شناسه پیدا نشد. شناسه را بررسی کن و دوباره بفرست.");
      return json({ok:true});
    }
    const linked = await env.DB.prepare("SELECT user_id FROM telegram_links WHERE telegram_user_id=?").bind(String(from.id)).first();
    if (linked?.user_id === target.id) {
      await telegramSend(env, chatId, "این حساب تلگرام از قبل به همین حساب سایت متصل است. برای دیدن امکانات /admin را بفرست.");
      return json({ok:true});
    }
    if (linked && linked.user_id !== target.id) {
      await telegramSend(env, chatId, "این حساب تلگرام قبلاً به یک حساب سایت دیگر متصل شده است. ابتدا اتصال قبلی را از همان حساب قطع کن.");
      return json({ok:true});
    }
    const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM telegram_link_requests WHERE telegram_user_id=? AND created_at>?").bind(String(from.id), new Date(Date.now()-60000).toISOString()).first();
    if (Number(recent?.n || 0) >= 5) {
      await telegramSend(env, chatId, "تعداد درخواست‌ها زیاد است. کمی بعد دوباره تلاش کن.");
      return json({ok:true});
    }
    await env.DB.prepare("UPDATE telegram_link_requests SET status='cancelled' WHERE telegram_user_id=? AND status='pending'").bind(String(from.id)).run();
    const requestId = id();
    const expiresAt = new Date(Date.now()+10*60*1000).toISOString();
    await env.DB.prepare("INSERT INTO telegram_link_requests(id,user_id,telegram_user_id,chat_id,username,first_name,status,expires_at) VALUES(?,?,?,?,?,?,'pending',?)")
      .bind(requestId,target.id,String(from.id),String(chatId),safeText(from.username,64),safeText(from.first_name,100),expiresAt).run();
    await telegramSend(env, chatId, "درخواست اتصال برای شناسه " + publicId + " ثبت شد. برای تأیید، وارد حساب همان شناسه در سایت شو و در بخش اتصال تلگرام، درخواست را تأیید کن.\n\nhttps://botforge.99lq9ohj-kfshcd.workers.dev/community.html\n\nاین درخواست تا ۱۰ دقیقه معتبر است.");
    return json({ok:true});
  }

  if (commandName === "/start") {
    const code = (parts[1] || "").toUpperCase().replace(/[^A-Z0-9]/g,"");
    if (!code) {
      await telegramSend(env, chatId, "سلام! 👋 برای اتصال حساب سایتت، شناسه ۴ رقمی را این‌طور بفرست:\n/connect 1234\n\nبعد وارد همان حساب در سایت شو و درخواست اتصال را تأیید کن.");
      return json({ok:true});
    }
    const record = await env.DB.prepare("SELECT id,user_id FROM telegram_link_codes WHERE code_hash=? AND used_at IS NULL AND expires_at>?").bind(await sha256(code),now()).first();
    if (!record) { await telegramSend(env, chatId, "این کد معتبر نیست یا منقضی شده. از داخل حساب سایت یک کد تازه بگیر."); return json({ok:true}); }
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO telegram_links(user_id,telegram_user_id,chat_id,username,first_name,linked_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET telegram_user_id=excluded.telegram_user_id,chat_id=excluded.chat_id,username=excluded.username,first_name=excluded.first_name,linked_at=excluded.linked_at")
          .bind(record.user_id,String(from.id),String(chatId),safeText(from.username,64),safeText(from.first_name,100),now()),
        env.DB.prepare("UPDATE telegram_link_codes SET used_at=? WHERE id=? AND used_at IS NULL").bind(now(),record.id)
      ]);
      const user = await env.DB.prepare("SELECT public_id,username FROM users WHERE id=?").bind(record.user_id).first();
      await telegramSend(env, chatId, "✅ حساب تلگرام با موفقیت به FXI BotForge متصل شد.\nشناسه سایت: " + user.public_id + "\nنام کاربری: @" + user.username + "\n\nاز این پس اعلان‌های مهم حسابت را همین‌جا دریافت می‌کنی.\nبرای امکانات مدیریتی: /admin");
    } catch (error) {
      console.error("Telegram account link failed:", error);
      await telegramSend(env, chatId, "اتصال انجام نشد؛ ممکن است این حساب تلگرام قبلاً به حساب دیگری وصل شده باشد.");
    }
    return json({ok:true});
  }
  if (commandName === "/help") {
    await telegramSend(env, chatId, "FXI BotForge 🤖\n/connect 1234 — اتصال حساب سایت\n/help — راهنما\n/admin — نمایش امکانات در دسترس");
    return json({ok:true});
  }
  if (chatType !== "private") {
    if (commandName === "/admin" || commandName === "/panel") await telegramSend(env, chatId, "🔒 منوی مدیریت فقط در گفت‌وگوی خصوصی ربات فعال است.");
    return json({ok:true});
  }

  const manager = await env.DB.prepare("SELECT u.id,u.public_id,u.username,u.role,u.status,u.permissions_json FROM telegram_links l JOIN users u ON u.id=l.user_id WHERE l.telegram_user_id=? LIMIT 1").bind(String(from.id)).first();
  const isManager = !!manager && manager.status === "active" && ["owner","admin"].includes(manager.role);
  const permissions = manager?.role === "owner" ? ["submissions","users","bots","audit","gifts"] : safePermissions(manager?.permissions_json);
  const can = key => manager?.role === "owner" || permissions.includes(key);
  const menu = {
    keyboard: [
      ...(can("submissions") ? [[{text:"📥 درخواست‌های جدید"}]] : []),
      ...((can("users") || can("bots")) ? [[...(can("users") ? [{text:"👥 کاربران"}] : []), ...(can("bots") ? [{text:"🤖 پروژه‌ها"}] : [])]] : []),
      ...(can("audit") ? [[{text:"🧾 گزارش فعالیت"}]] : []),
      ...(can("gifts") ? [[{text:"🎁 مدیریت هدایا"}]] : []),
      [[{text:"📊 آمار کلی"},{text:"🌐 پنل مدیریت"}]],
      [[{text:"❌ بستن منو"}]]
    ],
    resize_keyboard:true,
    is_persistent:true
  };
  const showMenu = async () => {
    if (!isManager) {
      await telegramSend(env,chatId,"⛔ برای این حساب دسترسی مدیریتی فعالی وجود ندارد.");
      return;
    }
    await telegramSend(env,chatId,"🛠 امکانات مدیریتی FXI BotForge\\nشناسه حساب: "+manager.public_id+"\\nفقط گزینه‌های فعال برایت نمایش داده شده‌اند.",menu);
  };
  const label = textValue;
  if (commandName === "/admin" || commandName === "/panel" || label === "🛠 منوی مدیریت") { await showMenu(); return json({ok:true}); }
  if (label === "❌ بستن منو") { await telegramSend(env,chatId,"منوی مدیریت بسته شد.",{remove_keyboard:true}); return json({ok:true}); }
  const action = ["📊 آمار کلی","📥 درخواست‌های جدید","👥 کاربران","🤖 پروژه‌ها","🧾 گزارش فعالیت","🎁 مدیریت هدایا","🌐 پنل مدیریت"].includes(label) ||
    ["/stats","/pending","/users","/projects","/activity","/gifts","/site"].includes(commandName);
  if (!action) { await telegramSend(env,chatId,"برای راهنما /help را بزن. با /admin می‌توانی امکانات در دسترس را ببینی."); return json({ok:true}); }
  if (!isManager) { await telegramSend(env,chatId,"⛔ برای این بخش دسترسی فعالی نداری."); return json({ok:true}); }

  if (label === "📊 آمار کلی" || commandName === "/stats") {
    const jobs = [];
    if (can("users")) jobs.push(["کاربران","SELECT COUNT(*) AS n FROM users"]);
    if (can("bots")) jobs.push(["پروژه‌های منتشرشده","SELECT COUNT(*) AS n FROM bots WHERE status='published'"]);
    if (can("submissions")) jobs.push(["درخواست‌های در انتظار","SELECT COUNT(*) AS n FROM submissions WHERE status='pending'"]);
    if (can("audit")) jobs.push(["دانلودها","SELECT COUNT(*) AS n FROM audit_logs WHERE action='bot.download'"]);
    const values = await Promise.all(jobs.map(async ([name,sql])=>({name,n:(await env.DB.prepare(sql).first())?.n??0})));
    await telegramSend(env,chatId,"📊 آمار قابل دسترس\n\n"+(values.map(x=>"• "+x.name+": "+x.n).join("\n")||"مجوز آماری فعالی نداری."),menu);
    return json({ok:true});
  }
  if (label === "📥 درخواست‌های جدید" || commandName === "/pending") {
    if (!can("submissions")) { await telegramSend(env,chatId,"⛔ دسترسی این بخش برای حسابت فعال نیست.",menu); return json({ok:true}); }
    const {results=[]}=await env.DB.prepare("SELECT id,title,category FROM submissions WHERE status='pending' ORDER BY created_at ASC LIMIT 8").all();
    const body=results.length?results.map((x,i)=>(i+1)+". "+safeText(x.title,90)+" | "+safeText(x.category,40)+"\nکد: "+x.id).join("\n\n"):"درخواست بررسی‌نشده‌ای وجود ندارد.";
    await telegramSend(env,chatId,"📥 درخواست‌های جدید\n\n"+body+"\n\nبرای تأیید یا رد، پنل را باز کن:\nhttps://botforge.99lq9ohj-kfshcd.workers.dev/admin.html",menu);
    return json({ok:true});
  }
  if (label === "👥 کاربران" || commandName === "/users") {
    if (!can("users")) { await telegramSend(env,chatId,"⛔ دسترسی این بخش برای حسابت فعال نیست.",menu); return json({ok:true}); }
    const {results=[]}=await env.DB.prepare("SELECT public_id,username,role,status FROM users ORDER BY created_at DESC LIMIT 10").all();
    await telegramSend(env,chatId,"👥 آخرین کاربران\n\n"+(results.map(x=>"• "+x.public_id+" | @"+safeText(x.username,24)+" | "+(x.status==="active"?"فعال":"غیرفعال")).join("\n")||"کاربری پیدا نشد."),menu);
    return json({ok:true});
  }
  if (label === "🤖 پروژه‌ها" || commandName === "/projects") {
    if (!can("bots")) { await telegramSend(env,chatId,"⛔ دسترسی این بخش برای حسابت فعال نیست.",menu); return json({ok:true}); }
    const {results=[]}=await env.DB.prepare("SELECT title,category,slug FROM bots WHERE status='published' ORDER BY published_at DESC LIMIT 10").all();
    await telegramSend(env,chatId,"🤖 پروژه‌های منتشرشده\n\n"+(results.map(x=>"• "+safeText(x.title,90)+" | "+safeText(x.category,40)+"\n"+x.slug).join("\n\n")||"پروژه‌ای منتشر نشده است."),menu);
    return json({ok:true});
  }
  if (label === "🧾 گزارش فعالیت" || commandName === "/activity") {
    if (!can("audit")) { await telegramSend(env,chatId,"⛔ دسترسی این بخش برای حسابت فعال نیست.",menu); return json({ok:true}); }
    const {results=[]}=await env.DB.prepare("SELECT action,target_type,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 10").all();
    await telegramSend(env,chatId,"🧾 آخرین فعالیت‌ها\n\n"+(results.map(x=>"• "+safeText(x.action,80)+" | "+safeText(x.target_type||"—",30)+"\n"+x.created_at).join("\n")||"گزارشی ثبت نشده است."),menu);
    return json({ok:true});
  }
  if (label === "🎁 مدیریت هدایا" || commandName === "/gifts") {
    if (!can("gifts")) { await telegramSend(env,chatId,"⛔ دسترسی این بخش برای حسابت فعال نیست.",menu); return json({ok:true}); }
    await telegramSend(env,chatId,"🎁 مدیریت کدهای هدیه از پنل انجام می‌شود:\nhttps://botforge.99lq9ohj-kfshcd.workers.dev/admin.html",menu);
    return json({ok:true});
  }
  if (label === "🌐 پنل مدیریت" || commandName === "/site") {
    await telegramSend(env,chatId,"🌐 پنل مدیریت BotForge:\nhttps://botforge.99lq9ohj-kfshcd.workers.dev/admin.html",menu);
    return json({ok:true});
  }
  await telegramSend(env,chatId,"دستور مدیریت شناخته نشد. /admin را بزن تا منو باز شود.",menu);
  return json({ok:true});
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
      return json({ ok: true, service: "FXI BotForge", database: "connected", storage: env.FILES ? "KV configured" : "missing", authentication: "user_id + username + password", edge: request.cf?.colo || null, checked_at: now() });
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
      return json({ ok: true, user_id: publicId, username, message: "حساب مالک ساخته شد. برای ورود از شناسه، نام کاربری و رمز استفاده کن." }, 201);
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
    if (!body || typeof body.user_id !== "string" || typeof body.username !== "string" || typeof body.password !== "string") return json({ error: "شناسه کاربری، نام کاربری و رمز عبور را کامل وارد کن." }, 400);
    const userId = normalizeUserId(body.user_id);
    const username = body.username.trim().toLowerCase();
    if (!/^\d{4}$/.test(userId) || !/^[a-z0-9_]{3,24}$/.test(username) || body.password.length > 200) return json({ error: "شناسه باید دقیقاً ۴ رقم و نام کاربری باید معتبر باشد." }, 400);
    const user = await env.DB.prepare("SELECT id,password_hash,password_salt,status,role FROM users WHERE public_id = ? AND username = ?").bind(userId, username).first();
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

  if (path === "/api/telegram/status" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const link = await env.DB.prepare("SELECT username,first_name,linked_at FROM telegram_links WHERE user_id=?").bind(auth.user.id).first();
    const {results:requests=[]} = await env.DB.prepare("SELECT id,username,first_name,created_at,expires_at FROM telegram_link_requests WHERE user_id=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 5").bind(auth.user.id,now()).all();
    return json({linked:!!link,link:link||null,requests,bot_username:"FxiCode_bot"});
  }
  if (path === "/api/telegram/link-code" && method === "POST") {
    if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    if (!env.TELEGRAM_BOT_TOKEN) return json({error:"اتصال ربات هنوز در تنظیمات سرور کامل نشده است."},503);
    const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const bytes=new Uint8Array(8); crypto.getRandomValues(bytes);
    const code=[...bytes].map(x=>alphabet[x%alphabet.length]).join("");
    const expiresAt=new Date(Date.now()+10*60*1000).toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM telegram_link_codes WHERE user_id=? AND used_at IS NULL").bind(auth.user.id),
      env.DB.prepare("INSERT INTO telegram_link_codes(id,user_id,code_hash,expires_at) VALUES(?,?,?,?)").bind(id(),auth.user.id,await sha256(code),expiresAt)
    ]);
    return json({ok:true,code,expires_at:expiresAt,bot_url:"https://t.me/FxiCode_bot"});
  }
  if (path === "/api/telegram/confirm" && method === "POST") {
    if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const body = await request.json().catch(()=>null);
    const requestId = safeText(body?.request_id,64);
    if (!requestId) return json({error:"درخواست اتصال معتبر نیست."},400);
    const pending = await env.DB.prepare("SELECT id,user_id,telegram_user_id,chat_id,username,first_name FROM telegram_link_requests WHERE id=? AND user_id=? AND status='pending' AND expires_at>?").bind(requestId,auth.user.id,now()).first();
    if (!pending) return json({error:"درخواست پیدا نشد یا منقضی شده است."},404);
    const existing = await env.DB.prepare("SELECT user_id FROM telegram_links WHERE telegram_user_id=?").bind(pending.telegram_user_id).first();
    if (existing && existing.user_id !== auth.user.id) return json({error:"این حساب تلگرام به حساب سایت دیگری متصل است."},409);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO telegram_links(user_id,telegram_user_id,chat_id,username,first_name,linked_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET telegram_user_id=excluded.telegram_user_id,chat_id=excluded.chat_id,username=excluded.username,first_name=excluded.first_name,linked_at=excluded.linked_at")
        .bind(auth.user.id,pending.telegram_user_id,pending.chat_id,pending.username||"",pending.first_name||"",now()),
      env.DB.prepare("UPDATE telegram_link_requests SET status='confirmed' WHERE id=? AND user_id=? AND status='pending'").bind(pending.id,auth.user.id)
    ]);
    await telegramSend(env,pending.chat_id,"اتصال حساب با موفقیت تأیید شد. از این پس اعلان‌های حساب سایتت را همین‌جا دریافت می‌کنی. برای دیدن امکانات /admin را بفرست.");
    await audit(env,auth.user.id,"telegram.account.link","telegram",pending.telegram_user_id,{public_id:auth.user.public_id});
    return json({ok:true});
  }

  if (path === "/api/telegram/unlink" && method === "POST") {
    if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    await env.DB.prepare("DELETE FROM telegram_links WHERE user_id=?").bind(auth.user.id).run();
    return json({ok:true});
  }

  if (path === "/api/community/me" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(auth.user.id).run();
    const [wallet, claim, rewards, purchases, transactions, entitlements] = await Promise.all([
      env.DB.prepare("SELECT balance FROM ncoin_wallets WHERE user_id=?").bind(auth.user.id).first(),
      env.DB.prepare("SELECT pattern,reward,claimed_at FROM ncoin_lucky_claims WHERE user_id=?").bind(auth.user.id).first(),
      env.DB.prepare("SELECT id,title,description,price FROM ncoin_rewards WHERE active=1 ORDER BY sort_order,price").all(),
      env.DB.prepare("SELECT p.id,p.price,p.status,p.created_at,r.title FROM ncoin_purchases p JOIN ncoin_rewards r ON r.id=p.reward_id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 20").bind(auth.user.id).all(),
      env.DB.prepare("SELECT amount,kind,description,created_at FROM ncoin_transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 12").bind(auth.user.id).all(),
      env.DB.prepare("SELECT id,entitlement_key,reward_id,activated_at,expires_at,status FROM ncoin_entitlements WHERE user_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?) ORDER BY activated_at DESC").bind(auth.user.id,now()).all()
    ]);
    return json({ user_id:auth.user.public_id, username:auth.user.username, balance:Number(wallet?.balance||0), lucky:luckyIdReward(auth.user.public_id), claim:claim||null, rewards:rewards.results||[], purchases:purchases.results||[], transactions:transactions.results||[], entitlements:entitlements.results||[] });
  }

  if (path === "/api/community/search" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const publicId = normalizeUserId(url.searchParams.get("id"));
    if (!/^\d{4}$/.test(publicId)) return json({error:"شناسه باید دقیقاً ۴ رقم باشد."},400);
    const user = await env.DB.prepare("SELECT id,public_id,username,role,created_at FROM users WHERE public_id=? AND status='active'").bind(publicId).first();
    if (!user) return json({error:"کاربری با این شناسه پیدا نشد."},404);
    const [projects, perks] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS count FROM bots WHERE uploader_id=? AND status='published'").bind(user.id).first(),
      env.DB.prepare("SELECT entitlement_key,expires_at FROM ncoin_entitlements WHERE user_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)").bind(user.id,now()).all()
    ]);
    return json({user:{public_id:user.public_id,username:user.username,role:user.role==="user"?"member":user.role,joined_at:user.created_at,projects:Number(projects?.count||0),perks:perks.results||[]}});
  }

  if (path === "/api/community/gift/redeem" && method === "POST") {
    if(!sameOrigin(request))return json({error:"درخواست نامعتبر است."},403);
    const auth=await requireUser(request,env);if(auth.response)return auth.response;
    const body=await request.json().catch(()=>null);
    const code=safeText(body?.code,32).toUpperCase().replace(/[^A-Z0-9]/g,"");
    if(code.length!==12)return json({error:"کد هدیه معتبر نیست."},400);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS gift_codes (id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL, amount INTEGER NOT NULL, max_uses INTEGER NOT NULL, used_count INTEGER NOT NULL DEFAULT 0, expires_at TEXT, active INTEGER NOT NULL DEFAULT 1, created_by TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS gift_redemptions (id TEXT PRIMARY KEY, gift_id TEXT NOT NULL, user_id TEXT NOT NULL, amount INTEGER NOT NULL, redeemed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(gift_id,user_id))").run();
    const gift=await env.DB.prepare("SELECT * FROM gift_codes WHERE code_hash=? AND active=1").bind(await sha256(code.match(/.{1,4}/g).join("-"))).first();
    if(!gift || gift.used_count>=gift.max_uses || (gift.expires_at && gift.expires_at<=now()))return json({error:"کد هدیه نامعتبر، منقضی یا تمام‌شده است."},404);
    try {
      const redemption = await env.DB.batch([
        env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(auth.user.id),
        env.DB.prepare("UPDATE gift_codes SET used_count=used_count+1 WHERE id=? AND active=1 AND used_count<max_uses AND (expires_at IS NULL OR expires_at>?)").bind(gift.id,now()),
        env.DB.prepare("INSERT INTO gift_redemptions(id,gift_id,user_id,amount) SELECT ?,?,?,? WHERE changes()=1").bind(id(),gift.id,auth.user.id,gift.amount),
        env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=? AND changes()=1").bind(gift.amount,now(),auth.user.id),
        env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) SELECT ?,?,?,?,? WHERE changes()=1").bind(id(),auth.user.id,gift.amount,"gift","دریافت کد هدیه")
      ]);
      const used=Number(redemption?.[1]?.meta?.changes??redemption?.[1]?.changes??0);
      const inserted=Number(redemption?.[2]?.meta?.changes??redemption?.[2]?.changes??0);
      if(!used||!inserted)return json({error:"ظرفیت این کد به پایان رسیده یا کد دیگر فعال نیست."},409);
    } catch (error) {
      if(/UNIQUE constraint failed/i.test(String(error?.message||error)))return json({error:"این کد را قبلاً در حساب خودت استفاده کرده‌ای."},409);
      throw error;
    }
    await audit(env,auth.user.id,"gift.redeem","gift",gift.id,{amount:gift.amount});
    return json({ok:true,amount:gift.amount,message:"کد هدیه با موفقیت ثبت شد."});
  }

  if (path === "/api/community/lucky/claim" && method === "POST") {
    if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(auth.user.id).run();
    const lucky = luckyIdReward(auth.user.public_id);
    if (!lucky) return json({ok:false,eligible:false,message:"شناسه‌ات در دسته شناسه‌های رُند جایزه‌دار نیست؛ اما می‌توانی با فعالیت در BotForge سکه جمع کنی."},200);
    const claimId = id();
    const claimResults = await env.DB.batch([
      env.DB.prepare("INSERT OR IGNORE INTO ncoin_lucky_claims(user_id,pattern,reward) VALUES(?,?,?)").bind(auth.user.id,lucky.pattern,lucky.reward),
      env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=? AND changes()=1").bind(lucky.reward,now(),auth.user.id),
      env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) SELECT ?,?,?,?,? WHERE changes()=1").bind(claimId,auth.user.id,lucky.reward,"lucky_id","جایزه شناسه رُند: "+lucky.title)
    ]);
    const changes = Number(claimResults?.[0]?.meta?.changes ?? claimResults?.[0]?.changes ?? 0);
    if (!changes) return json({ok:true,claimed:false,message:"جایزه شناسه‌ات قبلاً دریافت شده است."});
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
    const instant = {
      "profile-badge": { key:"profile_badge", days:null },
      "profile-frame": { key:"profile_frame", days:null },
      "profile-theme": { key:"profile_theme", days:null },
      "creator-spotlight": { key:"creator_spotlight", days:7 },
      "creator-spotlight-plus": { key:"creator_spotlight_plus", days:14 },
      "featured-project": { key:"featured_project", days:1, project:true },
      "project-feature-24h": { key:"featured_project", days:1, project:true },
      "project-feature-7d": { key:"featured_project", days:7, project:true },
      "project-promotion-month": { key:"featured_project", days:30, project:true }
    }[reward.id] || null;
    let featuredProject = null;
    if (instant?.project) {
      featuredProject = await env.DB.prepare("SELECT id,title,featured_until FROM bots WHERE uploader_id=? AND status='published' ORDER BY published_at DESC LIMIT 1").bind(auth.user.id).first();
      if (!featuredProject) return json({error:"برای فعال‌سازی این جایزه، ابتدا حداقل یک پروژه منتشرشده داشته باش."},400);
    }
    if (instant && !instant.days) {
      const already = await env.DB.prepare("SELECT id FROM ncoin_entitlements WHERE user_id=? AND entitlement_key=? AND status='active' AND expires_at IS NULL LIMIT 1").bind(auth.user.id,instant.key).first();
      if (already) return json({error:"این مزیت دائمی را قبلاً فعال کرده‌ای."},409);
    }
    await env.DB.prepare("INSERT OR IGNORE INTO ncoin_wallets(user_id,balance) VALUES(?,0)").bind(auth.user.id).run();
    const purchaseId=id(), purchasedAt=now();
    const featureBase = featuredProject?.featured_until && featuredProject.featured_until > purchasedAt ? Date.parse(featuredProject.featured_until) : Date.now();
    const expiresAt = instant?.days ? new Date((Number.isFinite(featureBase)?featureBase:Date.now())+instant.days*86400000).toISOString() : null;
    const update = await env.DB.prepare("UPDATE ncoin_wallets SET balance=balance-?,updated_at=? WHERE user_id=? AND balance>=?").bind(reward.price,purchasedAt,auth.user.id,reward.price).run();
    const changed = Number(update?.meta?.changes ?? update?.changes ?? 0);
    if (!changed) return json({error:"موجودی F COIN برای خرید این جایزه کافی نیست."},400);
    try {
      const statements = [
        env.DB.prepare("INSERT INTO ncoin_purchases(id,user_id,reward_id,price,status) VALUES(?,?,?,?,?)").bind(purchaseId,auth.user.id,reward.id,reward.price,instant?"delivered":"pending"),
        env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) VALUES(?,?,?,?,?)").bind(id(),auth.user.id,-reward.price,"purchase","خرید: "+reward.title)
      ];
      if (instant) statements.push(env.DB.prepare("INSERT INTO ncoin_entitlements(id,user_id,reward_id,entitlement_key,activated_at,expires_at,status,metadata_json) VALUES(?,?,?,?,?,?, 'active', ?)").bind(id(),auth.user.id,reward.id,instant.key,purchasedAt,expiresAt,featuredProject?JSON.stringify({project_id:featuredProject.id,project_title:featuredProject.title}):null));
      if (featuredProject) statements.push(env.DB.prepare("UPDATE bots SET featured_until=? WHERE id=? AND uploader_id=?").bind(expiresAt,featuredProject.id,auth.user.id));
      await env.DB.batch(statements);
    } catch (error) {
      await env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=?").bind(reward.price,now(),auth.user.id).run();
      throw error;
    }
    await audit(env,auth.user.id,"ncoin.reward.purchase","reward",reward.id,{purchase_id:purchaseId,price:reward.price,instant:!!instant,entitlement:instant?.key||null});
    if (instant) await notify(env,auth.user.id,"جایزه شما فعال شد ✨","«"+reward.title+"» بلافاصله فعال شد.","success");
    return json({ok:true,purchase_id:purchaseId,activated:!!instant,message:instant?"خرید موفق بود؛ جایزه همین حالا فعال شد.":"سفارش ثبت شد و برای آماده‌سازی در صف قرار گرفت."},201);
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

  if (path === "/api/announcements" && method === "GET") {
    const {results=[]}=await env.DB.prepare("SELECT id,title,body,kind,gift_code,gift_amount,gift_max_uses,image_url,created_at,expires_at FROM announcements WHERE active=1 AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at DESC LIMIT 5").bind(now()).all();
    return json({items:results||[]},200,{"cache-control":"public, max-age=0, s-maxage=20, stale-while-revalidate=40"});
  }

  if (path === "/api/public/stats" && method === "GET") {
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
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
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
    const { results } = await env.DB.prepare("SELECT id,slug,title,description,category,original_filename,file_size,published_at,featured_until FROM bots WHERE status='published' ORDER BY CASE WHEN featured_until IS NOT NULL AND featured_until>? THEN 0 ELSE 1 END, featured_until DESC, published_at DESC LIMIT 100").bind(now()).all();
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
    const auth = await requireUser(request, env);
    if (auth.response) return auth.response;
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
    if (path === "/api/admin/telegram/register-webhook" && method === "POST") {
      if (!sameOrigin(request)) return json({error:"درخواست نامعتبر است."},403);
      if (admin.user.role !== "owner") return json({error:"فقط مالک اصلی می‌تواند وب‌هوک ربات را ثبت کند."},403);
      if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_WEBHOOK_SECRET) return json({error:"ابتدا TELEGRAM_BOT_TOKEN و TELEGRAM_WEBHOOK_SECRET را در Cloudflare Worker Secrets تنظیم کن."},503);
      const base="https://api.telegram.org/bot"+env.TELEGRAM_BOT_TOKEN+"/";
      const identity=await fetch(base+"getMe").then(r=>r.json()).catch(()=>null);
      if (!identity?.ok || identity.result?.username?.toLowerCase()!=="fxicode_bot") return json({error:"توکن واردشده متعلق به @FxiCode_bot نیست یا معتبر نیست."},400);
      const hook=await fetch(base+"setWebhook",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({url:"https://botforge.99lq9ohj-kfshcd.workers.dev/telegram/webhook",secret_token:env.TELEGRAM_WEBHOOK_SECRET,allowed_updates:["message"],drop_pending_updates:false})}).then(r=>r.json()).catch(()=>null);
      if(!hook?.ok)return json({error:hook?.description||"ثبت وب‌هوک در تلگرام ناموفق بود."},502);
      const commands=await fetch(base+"setMyCommands",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({commands:[{command:"start",description:"شروع ربات"},{command:"connect",description:"اتصال با شناسه سایت"},{command:"menu",description:"منوی حساب کاربری"},{command:"account",description:"اطلاعات حساب"},{command:"projects",description:"پروژه‌های من"},{command:"submit",description:"ارسال پروژه جدید"},{command:"wallet",description:"کیف پول N Coin"},{command:"rewards",description:"فروشگاه جوایز"},{command:"gift",description:"ثبت کد هدیه"},{command:"notifications",description:"اعلان‌ها"},{command:"support",description:"پشتیبانی"},{command:"help",description:"راهنمای ربات"},{command:"admin",description:"امکانات مدیریتی"}]})}).then(r=>r.json()).catch(()=>null);
      if(!commands?.ok) console.warn("Telegram command menu registration failed:",commands?.description||"unknown");
      await audit(env,admin.user.id,"telegram.webhook.register","telegram_bot","FxiCode_bot",{webhook:"/telegram/webhook",commands:!!commands?.ok});
      return json({ok:true,bot_username:identity.result.username,webhook:"https://botforge.99lq9ohj-kfshcd.workers.dev/telegram/webhook"});
    }
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
        const allowed = ["submissions","users","bots","audit","gifts","announcements"];
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
        const body=await request.json().catch(()=>null), allowed=["submissions","users","bots","audit","gifts","announcements"];
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

    if (path.startsWith("/api/admin/announcements")) {
      if (admin.user.role !== "owner" && !safePermissions(admin.user.permissions_json).includes("announcements")) return json({error:"دسترسی انتشار اطلاع‌رسانی برای این حساب فعال نیست."},403);
      if (path === "/api/admin/announcements" && method === "GET") {
        const {results=[]}=await env.DB.prepare("SELECT id,title,body,kind,gift_code,gift_amount,gift_max_uses,image_url,active,created_at,expires_at FROM announcements ORDER BY created_at DESC LIMIT 100").all();
        return json({items:results||[]});
      }
      if (path === "/api/admin/announcements" && method === "POST") {
        if(!sameOrigin(request))return json({error:"درخواست نامعتبر است."},403);
        const body=await request.json().catch(()=>null);
        const kind=body?.kind==="gift"?"gift":"notice";
        const title=safeText(body?.title,100),message=safeText(body?.body,1200);
        const imageUrl=safeText(body?.image_url,500)||"/assets/cyrus-hero.webp";
        const expiryDate=body?.expires_at?new Date(body.expires_at):null;
        const expiry=expiryDate&&!Number.isNaN(expiryDate.getTime())?expiryDate.toISOString():null;
        if(title.length<3||message.length<2||(body?.expires_at&&(!expiry||expiry<=now())))return json({error:"عنوان، متن یا تاریخ انقضا معتبر نیست."},400);
        if(!(imageUrl.startsWith("/")&&!imageUrl.startsWith("//"))&&!imageUrl.startsWith("https://"))return json({error:"آدرس تصویر باید مسیر داخلی یا HTTPS باشد."},400);
        let giftCode=null,amount=null,maxUses=null;
        const announcementId=id();
        const announcementStatements=[];
        if(kind==="gift"){
          amount=Math.floor(Number(body?.amount));maxUses=Math.floor(Number(body?.max_uses));
          if(!Number.isInteger(amount)||amount<1||amount>1000000||!Number.isInteger(maxUses)||maxUses<1||maxUses>10000)return json({error:"مقدار سکه و تعداد دفعات استفاده معتبر نیست."},400);
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS gift_codes (id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL, amount INTEGER NOT NULL, max_uses INTEGER NOT NULL, used_count INTEGER NOT NULL DEFAULT 0, expires_at TEXT, active INTEGER NOT NULL DEFAULT 1, created_by TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
          const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789",bytes=new Uint8Array(12);crypto.getRandomValues(bytes);
          giftCode=Array.from(bytes,b=>alphabet[b%alphabet.length]).join("").match(/.{1,4}/g).join("-");
          announcementStatements.push(env.DB.prepare("INSERT INTO gift_codes(id,code_hash,code_hint,amount,max_uses,expires_at,created_by) VALUES(?,?,?,?,?,?,?)").bind(id(),await sha256(giftCode.toUpperCase()),giftCode.slice(-4),amount,maxUses,expiry,admin.user.id));
        }
        announcementStatements.push(env.DB.prepare("INSERT INTO announcements(id,title,body,kind,gift_code,image_url,active,created_by,expires_at,gift_amount,gift_max_uses) VALUES(?,?,?,?,?,?,1,?,?,?,?)").bind(announcementId,title,message,kind,giftCode,imageUrl,admin.user.id,expiry,amount,maxUses));
        await env.DB.batch(announcementStatements);
        await audit(env,admin.user.id,"announcement.create","announcement",announcementId,{kind,amount,max_uses:maxUses});
        return json({ok:true,id:announcementId,kind,gift_code:giftCode,amount,max_uses:maxUses},201);
      }
      const announcementMatch=path.match(/^\/api\/admin\/announcements\/([A-Za-z0-9_-]+)$/);
      if(announcementMatch&&method==="DELETE"){
        if(!sameOrigin(request))return json({error:"درخواست نامعتبر است."},403);
        const existing=await env.DB.prepare("SELECT kind,gift_code FROM announcements WHERE id=? AND active=1").bind(announcementMatch[1]).first();
        if(!existing)return json({error:"اطلاع‌رسانی پیدا نشد یا قبلاً غیرفعال شده است."},404);
        const statements=[env.DB.prepare("UPDATE announcements SET active=0 WHERE id=? AND active=1").bind(announcementMatch[1])];
        if(existing.kind==="gift"&&existing.gift_code){
          statements.push(env.DB.prepare("UPDATE gift_codes SET active=0 WHERE code_hash=?").bind(await sha256(existing.gift_code.toUpperCase())));
        }
        await env.DB.batch(statements);
        await audit(env,admin.user.id,"announcement.disable","announcement",announcementMatch[1]);
        return json({ok:true});
      }
      return json({error:"روش درخواست پشتیبانی نمی‌شود."},405);
    }

    if (path.startsWith("/api/admin/gifts")) {
      if (admin.user.role !== "owner" && !safePermissions(admin.user.permissions_json).includes("gifts")) return json({error:"دسترسی ساخت کد هدیه برای این حساب فعال نیست."},403);
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS gift_codes (id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL, amount INTEGER NOT NULL, max_uses INTEGER NOT NULL, used_count INTEGER NOT NULL DEFAULT 0, expires_at TEXT, active INTEGER NOT NULL DEFAULT 1, created_by TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS gift_redemptions (id TEXT PRIMARY KEY, gift_id TEXT NOT NULL, user_id TEXT NOT NULL, amount INTEGER NOT NULL, redeemed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(gift_id,user_id))").run();
      if (path === "/api/admin/gifts" && method === "GET") {
        const {results}=await env.DB.prepare("SELECT id,code_hint,amount,max_uses,used_count,expires_at,active,created_at FROM gift_codes ORDER BY created_at DESC LIMIT 100").all();
        return json({items:results||[]});
      }
      if (path === "/api/admin/gifts" && method === "POST") {
        if(!sameOrigin(request))return json({error:"درخواست نامعتبر است."},403);
        const body=await request.json().catch(()=>null);
        const amount=Math.floor(Number(body?.amount)), maxUses=Math.floor(Number(body?.max_uses));
        const expiryDate=body?.expires_at ? new Date(body.expires_at) : null;
        const expiry=expiryDate && !Number.isNaN(expiryDate.getTime()) ? expiryDate.toISOString() : null;
        if(!Number.isInteger(amount)||amount<1||amount>1000000||!Number.isInteger(maxUses)||maxUses<1||maxUses>10000|| (body?.expires_at && (!expiry || expiry<=now())))return json({error:"مقدار سکه، تعداد استفاده یا تاریخ انقضا معتبر نیست."},400);
        const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        const bytes=new Uint8Array(12);crypto.getRandomValues(bytes);
        const code=Array.from(bytes,b=>alphabet[b%alphabet.length]).join("").match(/.{1,4}/g).join("-");
        const codeHash=await sha256(code.toUpperCase());
        const giftId=id();
        await env.DB.prepare("INSERT INTO gift_codes(id,code_hash,code_hint,amount,max_uses,expires_at,created_by) VALUES(?,?,?,?,?,?,?)").bind(giftId,codeHash,code.slice(-4),amount,maxUses,expiry,admin.user.id).run();
        await audit(env,admin.user.id,"gift.create","gift",giftId,{amount,max_uses:maxUses,expires_at:expiry});
        return json({ok:true,code,amount,max_uses:maxUses,expires_at:expiry},201);
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
        // Reject + refund must be one transaction. changes() prevents a second
        // concurrent rejection from refunding the same purchase twice.
        const refundResults = await env.DB.batch([
          env.DB.prepare("UPDATE ncoin_purchases SET status='rejected',updated_at=? WHERE id=? AND status NOT IN ('rejected','delivered')").bind(now(),purchase.id),
          env.DB.prepare("UPDATE ncoin_wallets SET balance=balance+?,updated_at=? WHERE user_id=? AND changes()=1").bind(purchase.price,now(),purchase.user_id),
          env.DB.prepare("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) SELECT ?,?,?,?,? WHERE changes()=1").bind(id(),purchase.user_id,purchase.price,"refund","بازگشت وجه خرید ردشده")
        ]);
        const changed = Number(refundResults?.[0]?.meta?.changes ?? refundResults?.[0]?.changes ?? 0);
        if (!changed) return json({error:"این درخواست قبلاً نهایی شده است."},409);
      } else {
        const updated = await env.DB.prepare("UPDATE ncoin_purchases SET status=?,updated_at=? WHERE id=? AND status NOT IN ('rejected','delivered')").bind(status,now(),purchase.id).run();
        const changed = Number(updated?.meta?.changes ?? updated?.changes ?? 0);
        if (!changed) return json({error:"این درخواست قبلاً نهایی شده است."},409);
      }
      await notify(env,purchase.user_id,"وضعیت سفارش F COIN تغییر کرد",status==="rejected"?"سفارش رد شد و سکه‌ها به کیف پول برگشتند.":status==="approved"?"سفارش تأیید شد و در صف انجام قرار گرفت.":"جایزه خریداری‌شده تحویل شد.","info");
      return json({ok:true,status});
    }

    const capability = path.includes("/submissions") ? "submissions" : path.includes("/users") ? "users" : path.includes("/bots") ? "bots" : path.includes("/audit") ? "audit" : path.includes("/gifts") ? "gifts" : null;
    if (admin.user.role !== "owner" && capability) {
      const permissions = safePermissions(admin.user.permissions_json);
      if (!permissions.includes(capability)) return json({error:"این دسترسی برای حساب مدیر فعال نیست."},403);
    }
    if (path === "/api/admin/overview" && method === "GET") {
      const permissions = admin.user.role === "owner"
        ? ["submissions", "users", "bots", "audit", "gifts"]
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
      if (admin.user.role === "owner") jobs.push(env.DB.prepare("SELECT COALESCE(SUM(balance),0) AS total, COUNT(*) AS wallets FROM ncoin_wallets").first().then(row => { result.fcoin_balance = row.total; result.fcoin_wallets = row.wallets; }));
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
    if (url.pathname === "/telegram/webhook" && request.method === "POST") {
      try { return await handleTelegramWebhook(request, env); }
      catch (error) { console.error("Telegram webhook failed:", error); return json({ok:false},500); }
    }
    if (url.pathname.startsWith("/api/")) {
      try { return await handleApi(request, env, url); }
      catch (error) { const requestId = id(); console.error("API request failed:", requestId, error); return json({ error: "ارتباط با سرویس کامل نشد. وضعیت اتصال را بررسی کن و دوباره تلاش کن.", request_id: requestId }, 500); }
    }
    const assetPath = url.pathname === "/" ? "/index.html" : url.pathname;
    const allowed = new Set(["/index.html", "/app.js", "/styles.css", "/login.html", "/dashboard.html", "/admin.html", "/setup-owner.html", "/community.html", "/owner-inbox.html", "/assets/cyrus-hero.webp"]);
    if (!allowed.has(assetPath)) return new Response("Not Found", { status: 404 });
    if (request.method !== "GET" && request.method !== "HEAD") return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET, HEAD" } });

    // The public homepage is only a preview. Every workspace page and its data
    // require an authenticated account; redirect guests to registration/login.
    const protectedPages = new Set(["/dashboard.html", "/admin.html", "/community.html", "/owner-inbox.html"]);
    const needsUser = protectedPages.has(assetPath) || assetPath === "/index.html" || assetPath === "/app.js";
    const user = needsUser ? await currentUser(request, env) : null;
    if (protectedPages.has(assetPath) && !user) {
      return Response.redirect(new URL("/login.html?next=" + encodeURIComponent(assetPath), url), 302);
    }
    if (assetPath === "/app.js" && !user) {
      return new Response("/* Sign in to access the BotForge catalog. */", { headers: { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } });
    }

    const cached = STATIC_ASSET_CACHE.get(assetPath);
    let asset = cached && cached.expiresAt > Date.now() ? cached.body : null;
    let source = cached && cached.expiresAt > Date.now() ? cached.source : "";

    // KV is the latest release source, but it must never hold the page open indefinitely.
    // Cache successful reads per isolate and temporarily bypass KV after a slow/failing read.
    if (asset === null && env.FILES && Date.now() >= STATIC_KV_COOLDOWN_UNTIL) {
      try {
        // Binary assets must be read as ArrayBuffer; decoding WebP as UTF-8 corrupts the image.
        const binaryAsset = assetPath.startsWith("/assets/");
        const read = env.FILES.get("static" + assetPath, binaryAsset ? "arrayBuffer" : "text");
        let timeoutId;
        try {
          asset = await Promise.race([
            read,
            new Promise(resolve => { timeoutId = setTimeout(() => resolve(null), 250); })
          ]);
        } finally {
          if (timeoutId) clearTimeout(timeoutId);
        }
        if (asset !== null) {
          source = "kv";
          STATIC_KV_COOLDOWN_UNTIL = 0;
          STATIC_ASSET_CACHE.set(assetPath, { body: asset, source, expiresAt: Date.now() + (binaryAsset ? 3600000 : 15000) });
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
      const contentType = assetPath.endsWith(".html") ? "text/html; charset=utf-8"
        : assetPath.endsWith(".css") ? "text/css; charset=utf-8"
        : assetPath.endsWith(".js") ? "application/javascript; charset=utf-8"
        : assetPath.endsWith(".webp") ? "image/webp"
        : "application/octet-stream";
      const cacheControl = assetPath.endsWith(".html") ? "no-store"
        : assetPath.startsWith("/assets/") ? "public, max-age=3600, stale-while-revalidate=86400"
        : "public, max-age=300, stale-while-revalidate=3600";
      return new Response(request.method === "HEAD" ? null : asset, { headers: { "content-type": contentType, "cache-control": cacheControl, "x-fxi-static-source": source || "memory", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=(), microphone=(), geolocation=()" } });
    }
    return new Response("Static asset temporarily unavailable", { status: 503, headers: { "cache-control": "no-store", "retry-after": "5", "content-type": "text/plain; charset=utf-8" } });
  }
};
