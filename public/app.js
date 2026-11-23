const list = document.querySelector("#bot-list");
const count = document.querySelector("#bot-count");
const search = document.querySelector("#catalog-search");
const category = document.querySelector("#catalog-category");
let allBots = [];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function renderBots() {
  const term = (search?.value || "").trim().toLocaleLowerCase("fa");
  const selectedCategory = category?.value || "";
  const filtered = allBots.filter((bot) => {
    const haystack = [bot.title, bot.description, bot.category].join(" ").toLocaleLowerCase("fa");
    return (!term || haystack.includes(term)) && (!selectedCategory || bot.category === selectedCategory);
  });
  count.textContent = `${filtered.length} از ${allBots.length} سورس`;
  if (!filtered.length) {
    list.innerHTML = '<div class="empty-state">چیزی با این جست‌وجو پیدا نشد.</div>';
    return;
  }
  list.innerHTML = filtered.map((bot) => `
    <article class="bot-card">
      <span class="bot-meta">${escapeHtml(bot.category)} · ${(Number(bot.file_size) / 1024).toFixed(0)} KB</span>
      <h3>${escapeHtml(bot.title)}</h3>
      <p>${escapeHtml(bot.description)}</p>
      <a class="text-link" href="/api/bots/${encodeURIComponent(bot.slug)}/download" download>دریافت فایل ZIP ←</a>
    </article>
  `).join("");
}

async function loadBots() {
  try {
    const response = await fetch("/api/bots", { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error("catalog unavailable");
    const data = await response.json();
    allBots = Array.isArray(data.items) ? data.items : [];
    renderBots();
    if (!allBots.length) count.textContent = "۰ سورس منتشرشده";
  } catch {
    count.textContent = "اتصال موقتاً در دسترس نیست";
    list.innerHTML = '<div class="empty-state">فعلاً دریافت فهرست ممکن نیست. کمی بعد دوباره تلاش کن.</div>';
  }
}

search?.addEventListener("input", renderBots);
category?.addEventListener("change", renderBots);
loadBots();
