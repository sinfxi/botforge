const list = document.querySelector("#bot-list");
const count = document.querySelector("#bot-count");
const search = document.querySelector("#catalog-search");
const category = document.querySelector("#catalog-category");
const liveStatus = document.querySelector("#live-status");
const lastUpdated = document.querySelector("#catalog-updated");
const refreshButton = document.querySelector("#catalog-refresh");
let allBots = [], savedSlugs = new Set(), loggedIn = false, refreshing = false, lastCatalogSignature = "", retryTimer = null;
async function fetchJson(url, options = {}) {
 const controller = new AbortController();
 const timeout = Number(options.timeout) || 9000;
 const timer = setTimeout(() => controller.abort(), timeout);
 const { timeout: ignored, ...fetchOptions } = options;
 try {
  const response = await fetch(url, { ...fetchOptions, signal: controller.signal });
  if (!response.ok) throw new Error("HTTP " + response.status);
  return await response.json();
 } finally { clearTimeout(timer); }
}
function escapeHtml(value){return String(value??"").replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));}
function faNumber(value){return Number(value||0).toLocaleString("fa-IR");}
function setLive(online,message){if(!liveStatus)return;liveStatus.dataset.state=online?"online":"offline";const label=liveStatus.querySelector("[data-live-label]");if(label)label.textContent=message||(online?"اتصال زنده برقرار است":"ارتباط موقتاً قطع شده");}
function updateCategoryOptions(){if(!category)return;const selected=category.value;const categories=[...new Set(allBots.map(bot=>String(bot.category||"").trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,"fa"));category.innerHTML='<option value="">همه دسته‌ها</option>'+categories.map(item=>'<option value="'+escapeHtml(item)+'">'+escapeHtml(item)+'</option>').join("");category.value=categories.includes(selected)?selected:"";}
function renderBots(){
 if(!list)return;const term=(search?.value||"").trim().toLocaleLowerCase("fa"),selectedCategory=category?.value||"";
 const filtered=allBots.filter(bot=>{const haystack=[bot.title,bot.description,bot.category,bot.original_filename].join(" ").toLocaleLowerCase("fa");return(!term||haystack.includes(term))&&(!selectedCategory||bot.category===selectedCategory);});
 if(count)count.textContent=faNumber(filtered.length)+" از "+faNumber(allBots.length)+" پروژه";
 if(!filtered.length){list.innerHTML='<div class="empty-state"><span>⌕</span><b>'+(allBots.length?"چیزی با این جست‌وجو پیدا نشد.":"کتابخانه هنوز منتظر اولین پروژه است.")+'</b><small>'+(allBots.length?"عبارت یا دسته‌بندی دیگری را امتحان کن.":"بعد از تأیید اولین پروژه، اینجا نمایش داده می‌شود.")+'</small></div>';return;}
 list.innerHTML=filtered.map((bot,index)=>{const size=Number(bot.file_size)||0,sizeLabel=size>=1048576?(size/1048576).toFixed(1)+" MB":Math.max(1,Math.round(size/1024))+" KB",filename=String(bot.original_filename||"فایل پروژه"),ext=filename.includes(".")?filename.split(".").pop().toUpperCase():"FILE",date=bot.published_at?new Date(bot.published_at).toLocaleDateString("fa-IR"):"تازه منتشرشده";return '<article class="bot-card" style="--card-index:'+index+'"><div class="bot-card-topline"><span class="bot-meta">'+escapeHtml(bot.category||"سایر")+'</span><span class="file-kind">'+escapeHtml(ext)+'</span></div><h3>'+escapeHtml(bot.title)+'</h3><p>'+escapeHtml(bot.description)+'</p><div class="bot-card-foot"><small>'+escapeHtml(sizeLabel)+' · '+escapeHtml(date)+'</small><a class="text-link" href="/api/bots/'+encodeURIComponent(bot.slug)+'/download" download>دریافت فایل ←</a></div>'+(loggedIn?'<div class="bot-card-actions"><button type="button" class="quiet-button" data-favorite="'+escapeHtml(bot.slug)+'">'+(savedSlugs.has(bot.slug)?"★ ذخیره‌شده":"☆ ذخیره پروژه") + '</button><button type="button" class="quiet-button" data-report="'+escapeHtml(bot.slug)+'">گزارش مشکل</button></div>':'')+'</article>';}).join("");
}
async function loadCatalog({quiet=false}={}){if(refreshing)return;refreshing=true;if(list)list.setAttribute("aria-busy","true");if(refreshButton){refreshButton.disabled=true;refreshButton.classList.add("is-loading");}try{const data=await fetchJson("/api/bots",{headers:{accept:"application/json"},credentials:"same-origin",cache:"no-store",timeout:10000}),next=Array.isArray(data.items)?data.items:[],signature=JSON.stringify(next.map(bot=>[bot.id||bot.slug,bot.title,bot.description,bot.category,bot.original_filename,bot.file_size,bot.published_at])),changed=signature!==lastCatalogSignature;allBots=next;if(changed||!quiet){updateCategoryOptions();renderBots();lastCatalogSignature=signature;}if(retryTimer){clearTimeout(retryTimer);retryTimer=null;}setLive(true,"اتصال زنده برقرار است");if(lastUpdated)lastUpdated.textContent="آخرین همگام‌سازی: "+new Date().toLocaleTimeString("fa-IR",{hour:"2-digit",minute:"2-digit"});}catch(error){setLive(false,error?.name==="AbortError"?"پاسخ سرور بیش از حد طول کشید":"ارتباط با سرور برقرار نشد");if(!retryTimer&&!document.hidden)retryTimer=setTimeout(()=>{retryTimer=null;loadCatalog({quiet:true});},5000);if(!allBots.length&&list)list.innerHTML='<div class="empty-state"><b>اتصال به کتابخانه برقرار نشد.</b><small>اتصال اینترنت را بررسی کن یا دوباره تلاش کن.</small></div>';if(count&&!allBots.length)count.textContent="کتابخانه در دسترس نیست";}finally{refreshing=false;if(list)list.setAttribute("aria-busy","false");if(refreshButton){refreshButton.disabled=false;refreshButton.classList.remove("is-loading");}}}
async function loadPublicStats(){try{const stats=await fetchJson("/api/public/stats",{cache:"no-store",headers:{accept:"application/json"},timeout:7000});for(const[key,value]of Object.entries({projects:stats.projects,creators:stats.creators,downloads:stats.downloads})){const node=document.querySelector('[data-live-stat="'+key+'"]');if(node)node.textContent=faNumber(value);}}catch{}}

list?.addEventListener("click", async event => {
 const favorite=event.target.closest("[data-favorite]");
 if(favorite){
  const slug=favorite.dataset.favorite,wasSaved=savedSlugs.has(slug);
  favorite.disabled=true;
  try{
   const response=await fetch(wasSaved?"/api/favorites/"+encodeURIComponent(slug):"/api/favorites",{method:wasSaved?"DELETE":"POST",credentials:"same-origin",headers:{"content-type":"application/json","accept":"application/json"},body:wasSaved?undefined:JSON.stringify({slug})});
   const data=await response.json().catch(()=>({}));
   if(!response.ok)throw new Error(data.error||"ذخیره پروژه انجام نشد.");
   if(wasSaved)savedSlugs.delete(slug);else savedSlugs.add(slug);
   favorite.textContent=wasSaved?"☆ ذخیره پروژه":"★ ذخیره‌شده";
  }catch(error){alert(error.message)}finally{favorite.disabled=false}
  return;
 }
 const report=event.target.closest("[data-report]");
 if(report){
  const message=prompt("مشکل این پروژه را توضیح بده (حداقل ۱۰ کاراکتر):");
  if(!message)return;
  report.disabled=true;
  try{
   const response=await fetch("/api/reports",{method:"POST",credentials:"same-origin",headers:{"content-type":"application/json","accept":"application/json"},body:JSON.stringify({slug:report.dataset.report,category:"other",message})});
   const data=await response.json().catch(()=>({}));
   if(!response.ok)throw new Error(data.error||"ثبت گزارش ناموفق بود.");
   alert("گزارش ثبت شد. کد پیگیری: "+data.id);
  }catch(error){alert(error.message)}finally{report.disabled=false}
 }
});

search?.addEventListener("input",renderBots);category?.addEventListener("change",renderBots);
refreshButton?.addEventListener("click",()=>Promise.all([loadCatalog(),loadPublicStats()]));
window.addEventListener("online",()=>{loadCatalog();loadPublicStats();});window.addEventListener("offline",()=>setLive(false,"اینترنت دستگاه قطع شده است"));
document.addEventListener("visibilitychange",()=>{if(!document.hidden){loadCatalog({quiet:true});loadPublicStats();}});
loadCatalog();loadPublicStats();setInterval(()=>{if(!document.hidden){loadCatalog({quiet:true});loadPublicStats();}},30000);
fetch("/api/me",{credentials:"same-origin",cache:"no-store"}).then(r=>r.ok?r.json():null).then(async data=>{if(!data?.user)return;loggedIn=true;try{const fav=await fetchJson("/api/favorites",{credentials:"same-origin",cache:"no-store"});savedSlugs=new Set((fav.items||[]).map(x=>x.slug));renderBots();}catch{}document.body.classList.remove("guest-preview");const heroLink=document.querySelector('.hero-actions a[href="/login.html"]');if(heroLink){heroLink.href="#explore";heroLink.innerHTML="ورود به کتابخانه <span>←</span>";}const heroSecondary=document.querySelector(".hero-actions .text-link");if(heroSecondary){heroSecondary.href="/dashboard.html";heroSecondary.textContent="پروژه‌ات را منتشر کن ↗";}const loginLink=document.querySelector(".topbar > .button");if(loginLink){loginLink.href="/dashboard.html";loginLink.textContent="فضای شخصی ↗";}const dashboardLink=document.querySelector('.hero-actions a[href="/dashboard.html"]');if(dashboardLink)dashboardLink.textContent="رفتن به فضای شخصی ↗";if(["admin","owner"].includes(data.user.role)){const nav=document.querySelector(".topbar nav");if(nav&&!document.querySelector("[data-admin-nav]")){const link=document.createElement("a");link.href="/admin.html";link.dataset.adminNav="true";link.textContent="مرکز مدیریت";nav.append(link);}}}).catch(()=>{});
