const list = document.querySelector("#bot-list");
const count = document.querySelector("#bot-count");
const search = document.querySelector("#catalog-search");
const category = document.querySelector("#catalog-category");
const liveStatus = document.querySelector("#live-status");
const lastUpdated = document.querySelector("#catalog-updated");
const refreshButton = document.querySelector("#catalog-refresh");
let allBots = [], savedSlugs = new Set(), loggedIn = false, refreshing = false, lastCatalogSignature = "", retryTimer = null, savedOnly = false;
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
function updateCategoryOptions(){if(!category)return;const selected=category.value;const categories=[...new Set(allBots.map(bot=>String(bot.category||"").trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,"fa"));category.innerHTML='<option value="">همه دسته‌ها</option>'+categories.map(item=>'<option value="'+escapeHtml(item)+'">'+escapeHtml(item)+'</option>').join("");category.value=categories.includes(selected)?selected:"";renderCategoryChips();}
function renderCategoryChips(){const wrap=document.querySelector("#category-chips");if(!wrap)return;const cats=[...new Set(allBots.map(bot=>String(bot.category||"").trim()).filter(Boolean))].sort((x,y)=>x.localeCompare(y,"fa"));wrap.innerHTML='<button type="button" class="category-chip '+(!category?.value?'is-active':'')+'" data-category="">همه پروژه‌ها</button>'+cats.map(item=>'<button type="button" class="category-chip '+(category?.value===item?'is-active':'')+'" data-category="'+escapeHtml(item)+'">'+escapeHtml(item)+'</button>').join("");}
function renderBots(){
 if(!list)return;
 const term=(search?.value||"").trim().toLocaleLowerCase("fa"),selectedCategory=category?.value||"",sort=document.querySelector("#catalog-sort")?.value||"newest";
 let filtered=allBots.filter(bot=>{const haystack=[bot.title,bot.description,bot.category,bot.original_filename].join(" ").toLocaleLowerCase("fa");return(!term||haystack.includes(term))&&(!selectedCategory||bot.category===selectedCategory)&&(!savedOnly||savedSlugs.has(bot.slug));});
 filtered.sort((x,y)=>sort==="oldest"?new Date(x.published_at||0)-new Date(y.published_at||0):sort==="name"?String(x.title||"").localeCompare(String(y.title||""),"fa"):sort==="size"?Number(y.file_size||0)-Number(x.file_size||0):new Date(y.published_at||0)-new Date(x.published_at||0));
 if(count)count.textContent=faNumber(filtered.length)+" پروژه"+(filtered.length!==allBots.length?" از "+faNumber(allBots.length):"");
 const clear=document.querySelector("#catalog-clear");if(clear)clear.hidden=!term;
 if(!filtered.length){list.innerHTML='<div class="empty-state"><span>⌕</span><b>'+(savedOnly?"هنوز پروژه‌ای ذخیره نکرده‌ای.":allBots.length?"چیزی با این فیلتر پیدا نشد.":"کتابخانه هنوز منتظر اولین پروژه است.")+'</b><small>'+(savedOnly?"پروژه‌های موردعلاقه‌ات را با دکمه ذخیره کنار هر کارت نگه دار.":"عبارت جست‌وجو یا دسته‌بندی را تغییر بده.")+'</small></div>';return;}
 list.innerHTML=filtered.map((bot,index)=>{const size=Number(bot.file_size)||0,sizeLabel=size>=1048576?(size/1048576).toFixed(1)+" MB":Math.max(1,Math.round(size/1024))+" KB",filename=String(bot.original_filename||"فایل پروژه"),ext=filename.includes(".")?filename.split(".").pop().toUpperCase():"FILE",date=bot.published_at?new Date(bot.published_at).toLocaleDateString("fa-IR"):"تازه منتشرشده";return '<article class="bot-card" style="--card-index:'+index+'"><div class="bot-card-topline"><span class="bot-meta">'+escapeHtml(bot.category||"سایر")+'</span><span class="file-kind">'+escapeHtml(ext)+'</span></div><h3>'+escapeHtml(bot.title)+'</h3><p>'+escapeHtml(bot.description)+'</p><div class="bot-card-foot"><small>'+escapeHtml(sizeLabel)+' · '+escapeHtml(date)+'</small><a class="text-link" href="/api/bots/'+encodeURIComponent(bot.slug)+'/download" download>دریافت فایل ←</a></div>'+(loggedIn?'<div class="bot-card-actions"><button type="button" class="quiet-button" data-favorite="'+escapeHtml(bot.slug)+'">'+(savedSlugs.has(bot.slug)?"★ ذخیره‌شده":"☆ ذخیره پروژه")+'</button><button type="button" class="quiet-button" data-report="'+escapeHtml(bot.slug)+'">گزارش مشکل</button></div>':'')+'</article>';}).join("");
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
   renderBots();
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

search?.addEventListener("input",renderBots);category?.addEventListener("change",()=>{renderCategoryChips();renderBots();});document.querySelector("#catalog-sort")?.addEventListener("change",renderBots);document.querySelector("#catalog-clear")?.addEventListener("click",()=>{if(search)search.value="";renderBots();search?.focus();});document.querySelector("#category-chips")?.addEventListener("click",event=>{const chip=event.target.closest("[data-category]");if(!chip||!category)return;category.value=chip.dataset.category||"";renderCategoryChips();renderBots();});document.querySelector("#saved-filter")?.addEventListener("click",event=>{savedOnly=!savedOnly;event.currentTarget.setAttribute("aria-pressed",String(savedOnly));event.currentTarget.textContent=savedOnly?"★ نمایش همه پروژه‌ها":"☆ فقط ذخیره‌شده‌ها";renderBots();});
refreshButton?.addEventListener("click",()=>Promise.all([loadCatalog(),loadPublicStats()]));
window.addEventListener("online",()=>{loadCatalog();loadPublicStats();});window.addEventListener("offline",()=>setLive(false,"اینترنت دستگاه قطع شده است"));
document.addEventListener("visibilitychange",()=>{if(!document.hidden){loadCatalog({quiet:true});loadPublicStats();}});
loadCatalog();loadPublicStats();setInterval(()=>{if(!document.hidden){loadCatalog({quiet:true});loadPublicStats();}},30000);
fetch("/api/me",{credentials:"same-origin",cache:"no-store"}).then(r=>r.ok?r.json():null).then(async data=>{if(!data?.user)return;loggedIn=true;const savedFilter=document.querySelector("#saved-filter");if(savedFilter)savedFilter.hidden=false;try{const fav=await fetchJson("/api/favorites",{credentials:"same-origin",cache:"no-store"});savedSlugs=new Set((fav.items||[]).map(x=>x.slug));renderBots();}catch{}document.body.classList.remove("guest-preview");const heroLink=document.querySelector('.hero-actions a[href="/login.html"]');if(heroLink){heroLink.href="#explore";heroLink.innerHTML="ورود به کتابخانه <span>←</span>";}const heroSecondary=document.querySelector(".hero-actions .text-link");if(heroSecondary){heroSecondary.href="/dashboard.html";heroSecondary.textContent="پروژه‌ات را منتشر کن ↗";}const loginLink=document.querySelector(".topbar > .button");if(loginLink){loginLink.href="/dashboard.html";loginLink.textContent="فضای شخصی ↗";}const dashboardLink=document.querySelector('.hero-actions a[href="/dashboard.html"]');if(dashboardLink)dashboardLink.textContent="رفتن به فضای شخصی ↗";if(["admin","owner"].includes(data.user.role)){const nav=document.querySelector(".topbar nav");if(nav&&!document.querySelector("[data-admin-nav]")){const link=document.createElement("a");link.href="/admin.html";link.dataset.adminNav="true";link.textContent="مرکز مدیریت";nav.append(link);}}}).catch(()=>{});


// FXI DIMENSION — original realtime ray-marched object (no image or 3D library).
(()=>{
 const canvas=document.getElementById("fxi-dimension");
 if(!canvas)return;
 const gl=canvas.getContext("webgl",{alpha:true,antialias:true,powerPreference:"low-power"});
 if(!gl){canvas.classList.add("dimension-fallback");return;}
 const vertex=`attribute vec2 p; void main(){gl_Position=vec4(p,0.,1.);}`;
 const fragment=`precision highp float;
 uniform vec2 r; uniform float t; uniform vec2 m;
 mat2 rot(float a){float c=cos(a),s=sin(a);return mat2(c,-s,s,c);}
 float sdTorus(vec3 p,vec2 q){return length(vec2(length(p.xz)-q.x,p.y))-q.y;}
 float scene(vec3 p){
  vec3 q=p;
  q.xz=rot(.42*sin(t*.22)+m.x*.32)*q.xz;
  q.xy=rot(.58+m.y*.22)*q.xy;
  float a=sdTorus(q,vec2(.77,.105));
  vec3 b=p;b.yz=rot(1.04+t*.13)*b.yz;b.xy=rot(-.66)*b.xy;
  float c=sdTorus(b,vec2(.77,.075));
  vec3 d=p;d.xz=rot(1.57-t*.11)*d.xz;d.yz=rot(.42)*d.yz;
  float e=sdTorus(d,vec2(.77,.052));
  float core=length(p)-.37;
  float rings=min(a,min(c,e));
  return min(rings,core);
 }
 vec3 normalAt(vec3 p){vec2 e=vec2(.001,0.);return normalize(vec3(scene(p+e.xyy)-scene(p-e.xyy),scene(p+e.yxy)-scene(p-e.yxy),scene(p+e.yyx)-scene(p-e.yyx)));}
 void main(){
  vec2 uv=(gl_FragCoord.xy-.5*r)/r.y;
  vec3 ro=vec3(0.,0.,3.35),rd=normalize(vec3(uv,-1.85));
  float travel=0.,dist=0.;vec3 pos;
  for(int i=0;i<100;i++){pos=ro+rd*travel;dist=scene(pos);if(dist<.0015||travel>8.)break;travel+=dist*.82;}
  vec3 col=vec3(.025,.055,.043);
  if(travel<8.){
   vec3 n=normalAt(pos),light=normalize(vec3(-.55,.8,1.2)),view=normalize(ro-pos);
   float diff=max(dot(n,light),0.);
   float rim=pow(1.-max(dot(n,view),0.),2.4);
   float spec=pow(max(dot(reflect(-light,n),view),0.),42.);
   float bands=.5+.5*sin(atan(pos.z,pos.x)*7.+pos.y*8.);
   vec3 deep=vec3(.10,.25,.18),mint=vec3(.58,.82,.64),gold=vec3(.62,.48,.25);
   vec3 mat=mix(deep,mint,smoothstep(.15,.95,bands));
   mat=mix(mat,gold,smoothstep(.93,1.,bands)*.35);
   col=mat*(.22+diff*.8)+vec3(.55,.82,.63)*rim*.55+vec3(1.,.86,.58)*spec*.8;
   float fog=exp(-travel*.18);col=mix(vec3(.025,.055,.043),col,fog);
  }
  float vignette=1.-smoothstep(.35,1.25,length(uv));col*=.68+.32*vignette;
  gl_FragColor=vec4(col,1.);
 }`;
 const compile=(type,source)=>{const s=gl.createShader(type);gl.shaderSource(s,source);gl.compileShader(s);if(!gl.getShaderParameter(s,gl.COMPILE_STATUS))throw Error(gl.getShaderInfoLog(s));return s;};
 try{
  const program=gl.createProgram();gl.attachShader(program,compile(gl.VERTEX_SHADER,vertex));gl.attachShader(program,compile(gl.FRAGMENT_SHADER,fragment));gl.linkProgram(program);
  if(!gl.getProgramParameter(program,gl.LINK_STATUS))throw Error(gl.getProgramInfoLog(program));
  gl.useProgram(program);const buffer=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buffer);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),gl.STATIC_DRAW);
  const loc=gl.getAttribLocation(program,"p");gl.enableVertexAttribArray(loc);gl.vertexAttribPointer(loc,2,gl.FLOAT,false,0,0);
  const uniforms={r:gl.getUniformLocation(program,"r"),t:gl.getUniformLocation(program,"t"),m:gl.getUniformLocation(program,"m")};
  let pointer=[0,0],target=[0,0],raf=0,started=performance.now(),visible=true;
  const reduced=matchMedia("(prefers-reduced-motion: reduce)").matches;
  const resize=()=>{const box=canvas.getBoundingClientRect(),dpr=Math.min(devicePixelRatio||1,1.5);canvas.width=Math.max(1,Math.floor(box.width*dpr));canvas.height=Math.max(1,Math.floor(box.height*dpr));gl.viewport(0,0,canvas.width,canvas.height);};
  const move=e=>{const b=canvas.getBoundingClientRect();target=[((e.clientX-b.left)/b.width-.5)*2,((e.clientY-b.top)/b.height-.5)*-2];};
  canvas.addEventListener("pointermove",move,{passive:true});canvas.addEventListener("pointerleave",()=>target=[0,0]);
  const draw=now=>{if(!visible)return;pointer[0]+=(target[0]-pointer[0])*.045;pointer[1]+=(target[1]-pointer[1])*.045;gl.uniform2f(uniforms.r,canvas.width,canvas.height);gl.uniform1f(uniforms.t,reduced?0:(now-started)*.001);gl.uniform2f(uniforms.m,pointer[0],pointer[1]);gl.drawArrays(gl.TRIANGLES,0,6);if(!reduced)raf=requestAnimationFrame(draw);};
  const observer=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;if(visible){cancelAnimationFrame(raf);draw(performance.now());}else cancelAnimationFrame(raf);});observer.observe(canvas);
  new ResizeObserver(resize).observe(canvas);resize();draw(performance.now());
 }catch(err){canvas.classList.add("dimension-fallback");console.warn("FXI Dimension unavailable",err);}
})();
