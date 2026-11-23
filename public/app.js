const list = document.querySelector("#bot-list");
const count = document.querySelector("#bot-count");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

async function loadBots() {
  try {
    const response = await fetch("/api/bots", { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error("catalog unavailable");
    const data = await response.json();
    const items = Array.isArray(data.items) ? data.items : [];
    count.textContent = `${items.length} سورس منتشرشده`;
    if (!items.length) {
      list.innerHTML = '<div class="empty-state">هنوز سورسی منتشر نشده؛ اولین پروژه می‌تواند از تو باشد.</div>';
      return;
    }
    list.innerHTML = items.map((bot) => `
      <article class="bot-card">
        <span class="bot-meta">${escapeHtml(bot.category)}</span>
        <h3>${escapeHtml(bot.title)}</h3>
        <p>${escapeHtml(bot.description)}</p>
      </article>
    `).join("");
  } catch {
    count.textContent = "اتصال موقتاً در دسترس نیست";
    list.innerHTML = '<div class="empty-state">فعلاً دریافت فهرست ممکن نیست. کمی بعد دوباره تلاش کن.</div>';
  }
}

loadBots();
