// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
// GoProxy DNS v2.8.0: smart server cards + dashboard-wide polish.
// Design notes: Live-graph look everywhere (monotone curves, soft gradient fills, thin dashed
// grid, big tabular numbers). Inspirations: Apple HIG (system font, frosted-glass bars,
// Activity rings, spring motion), Stripe (KPI tile = value + delta vs baseline + sparkline),
// Vercel/Protocore (skeletons instead of spinners), Linear (sticky section nav, quiet chrome),
// Grafana (hover crosshair + heat grids), UniFi (smooth live curves), Tailscale (status pills).
// No external assets. Animations respect prefers-reduced-motion and pause when hidden.
(()=>{"use strict";
const $=id=>document.getElementById(id),esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const RM=matchMedia("(prefers-reduced-motion: reduce)");let calm=RM.matches;RM.addEventListener?.("change",e=>calm=e.matches);
const H=window.HELP||(window.HELP={});
H.v28smart=["Smart upstreams","Every upstream is probed once a minute the same way. Lookups race only the best few (by speed and success rate); every 20th lookup also tries one of the others so it can win its place back. Slow or failing upstreams are benched for 5 minutes.","3 racing, success near 100%, probe times under ~40 ms."];
H.v28speed=["Speed history","Saved on disk (30 days, fixed 5.5 MB). Uncached lookup time (average), 95th percentile of all answers, and the share answered from cache.","Cache share high (70%+), uncached time steady."];
H.v28kpi=["Smart summary","Totals for the selected range, compared with the range before it.","More cache, fewer failures."];
H.v28habit=["Habits","Which hours of the week are busy. A few minutes before an hour starts, the names you usually look up then are refreshed so they answer instantly. Learned from totals only; nothing per device.","Evenings brighter than nights."];
H.v28report=["Weekly report card","The last 7 days against the 7 before: cache share, speed, reliability, top domains and anything unusual.","Grade A or B."];
H.v28events=["Self-healing & security","What the server did on its own (benching an upstream, racing everybody, re-warming the cache) and any suspicious domains (random-looking names, possible DNS tunneling).","Empty, or a few benchings."];
H.v28set=["Smart settings","Each feature can be switched on or off. Threat feeds and blocking of suspicious domains are off until you switch them on. DNSSEC strict stops the CD=1 retry so a broken signature stays an error.","Defaults are fine for most homes."];
const api=async(u,o)=>{const r=await fetch(u,Object.assign({cache:"no-store"},o||{}));let j=null;try{j=await r.json()}catch(e){}if(!r.ok)throw new Error((j&&j.error)||r.statusText);return j};
const post=(u,b)=>api(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})});
const fmt=n=>Number(n||0).toLocaleString(),pct=v=>(100*(v||0)).toFixed((v||0)>.995||!v?0:1)+"%",ms=v=>v?(v<10?v.toFixed(1):Math.round(v))+" ms":"–";
// ---------- global polish ----------
const css=document.createElement("style");css.textContent=`
:root{--spring:cubic-bezier(.34,1.4,.64,1);--ease:cubic-bezier(.2,.8,.2,1);--glass:light-dark(rgba(245,245,247,.72),rgba(17,18,20,.68))}
:root[data-theme=light]{color-scheme:light}:root[data-theme=dark]{color-scheme:dark}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Inter","Segoe UI Variable",system-ui,sans-serif;letter-spacing:-.003em}
header{position:sticky;top:0;z-index:30;margin:-20px -20px 18px;padding:14px 20px;background:var(--glass);-webkit-backdrop-filter:saturate(180%) blur(20px);backdrop-filter:saturate(180%) blur(20px);border-bottom:1px solid var(--edge)}
@media (max-width:760px){header{position:static;margin:0 0 14px;padding:0;background:none;-webkit-backdrop-filter:none;backdrop-filter:none;border:0}}
.card{border:1px solid var(--edge);box-shadow:0 1px 2px rgba(0,0,0,.03);transition:box-shadow .35s var(--ease),transform .35s var(--spring),border-color .35s}
.card:hover{box-shadow:0 8px 30px rgba(0,0,0,.07);border-color:color-mix(in srgb,var(--accent) 18%,var(--edge))}
.grid.kpis{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.big,.v27big,.v28big{font-variant-numeric:tabular-nums;letter-spacing:-.025em}
.tog::after{transition:left .4s var(--spring),width .2s}
.btn,.seg button,.tog{transition:background .2s,color .2s,transform .25s var(--spring),box-shadow .2s}.btn:active,.seg button:active{transform:scale(.96)}
.dot.up{box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 60%,transparent);animation:v28pulse 2.4s ease-out infinite}
@keyframes v28pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 55%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
#pop{animation:v28pop .28s var(--spring);transform-origin:top left;-webkit-backdrop-filter:blur(20px);backdrop-filter:blur(20px);background:color-mix(in srgb,var(--surface) 88%,transparent)}
@keyframes v28pop{from{opacity:0;transform:scale(.92) translateY(-4px)}to{opacity:1;transform:none}}
.v28in{animation:v28rise .6s var(--ease) both}@keyframes v28rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.v28pane{animation:v28fade .4s var(--ease)}@keyframes v28fade{from{opacity:0;transform:translateY(6px) scale(.995)}to{opacity:1;transform:none}}
.v28sk{color:transparent!important;border-radius:8px;background:linear-gradient(90deg,var(--surface2) 25%,color-mix(in srgb,var(--surface2) 40%,var(--surface)) 50%,var(--surface2) 75%);background-size:200% 100%;animation:v28sh 1.4s linear infinite;min-width:3ch;display:inline-block}
@keyframes v28sh{to{background-position:-200% 0}}
.v28nav{position:sticky;top:var(--v28top,64px);z-index:20;display:flex;gap:2px;width:max-content;max-width:100%;overflow-x:auto;margin:0 auto 16px;padding:3px;border-radius:12px;background:var(--glass);-webkit-backdrop-filter:saturate(180%) blur(20px);backdrop-filter:saturate(180%) blur(20px);border:1px solid var(--edge);scrollbar-width:none}
.v28nav button{position:relative;z-index:1;border:0;background:none;font:inherit;font-size:13px;font-weight:550;color:var(--muted);padding:6px 14px;border-radius:9px;cursor:pointer;white-space:nowrap;transition:color .25s}
.v28nav button.on{color:var(--text)}.v28nav i{position:absolute;z-index:0;top:3px;bottom:3px;border-radius:9px;background:var(--surface);box-shadow:0 1px 3px rgba(0,0,0,.1);transition:left .45s var(--spring),width .45s var(--spring)}
@media (max-width:760px){.v28nav{top:6px}}
.v28g{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;margin-bottom:16px}
@media (max-width:760px){.v28g{grid-template-columns:1fr}}
.v28kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.v28k{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:600}
.v28big{font-size:28px;font-weight:650;line-height:1.15}
.v28d{white-space:nowrap;display:inline-block;font-size:11.5px;font-weight:600;border-radius:999px;padding:1px 7px;margin-left:6px;vertical-align:4px}.v28d.good{color:var(--green);background:color-mix(in srgb,var(--green) 13%,transparent)}.v28d.bad{color:var(--red);background:color-mix(in srgb,var(--red) 12%,transparent)}.v28d.flat{color:var(--muted);background:var(--surface2)}
.v28spark{width:100%;height:34px;display:block;margin-top:6px}
.v28up{display:grid;grid-template-columns:22px 1fr auto;gap:4px 10px;align-items:center;padding:8px 2px;border-top:1px solid color-mix(in srgb,var(--edge) 70%,transparent);transition:background .25s}
.v28up:first-child{border-top:0}.v28up:hover{background:color-mix(in srgb,var(--surface2) 55%,transparent);border-radius:10px}
.v28rk{font:650 12px system-ui;color:var(--muted);text-align:center}
.v28meter{position:relative;height:5px;border-radius:3px;background:var(--surface2);overflow:hidden;margin-top:5px}.v28meter i{position:absolute;inset:0 auto 0 0;border-radius:3px;transition:width .8s var(--spring)}
.v28pill{font-size:10.5px;font-weight:650;border-radius:999px;padding:1px 8px;margin-left:6px;letter-spacing:.02em}
.v28pill.race{color:var(--green);background:color-mix(in srgb,var(--green) 14%,transparent)}.v28pill.stand{color:var(--muted);background:var(--surface2)}.v28pill.bench{color:var(--amber);background:color-mix(in srgb,var(--amber) 15%,transparent)}.v28pill.down{color:var(--red);background:color-mix(in srgb,var(--red) 13%,transparent)}
.v28tip{position:fixed;z-index:60;pointer-events:none;padding:8px 11px;border-radius:11px;font-size:12px;line-height:1.5;background:color-mix(in srgb,var(--surface) 86%,transparent);-webkit-backdrop-filter:blur(18px);backdrop-filter:blur(18px);box-shadow:0 8px 30px rgba(0,0,0,.16),0 0 0 1px var(--edge);opacity:0;transform:translateY(4px) scale(.97);transition:opacity .18s,transform .25s var(--spring)}
.v28tip.on{opacity:1;transform:none}.v28tip b{font-variant-numeric:tabular-nums}
.v28ev{display:grid;grid-template-columns:10px 1fr auto;gap:10px;align-items:start;padding:8px 0;border-top:1px solid color-mix(in srgb,var(--edge) 60%,transparent);font-size:13px}
.v28ev:first-child{border-top:0}.v28ev i{width:8px;height:8px;border-radius:50%;margin-top:6px}
.v28rings{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.v28f{display:grid;grid-template-columns:1fr auto;gap:8px 12px;align-items:center;padding:7px 0;border-top:1px solid color-mix(in srgb,var(--edge) 55%,transparent)}.v28f:first-child{border-top:0}
.v28f select,.v28f input[type=number]{font:inherit;padding:5px 8px;border-radius:9px;border:1px solid var(--edge);background:transparent;color:inherit;width:84px}
.v28ta{width:100%;font:12px ui-monospace,monospace;padding:7px 9px;border-radius:10px;border:1px solid var(--edge);background:transparent;color:inherit;min-height:52px;box-sizing:border-box}
.v28empty{display:grid;place-items:center;text-align:center;padding:22px 10px;color:var(--muted);font-size:13px}.v28empty b{display:block;font-size:22px;margin-bottom:4px;opacity:.8}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
`;document.head.appendChild(css);
// theme: auto / light / dark (Apple-style three-way)
(()=>{const ctl=document.querySelector("header .ctl");if(!ctl)return;const s=document.createElement("div");s.className="seg";s.setAttribute("role","group");s.setAttribute("aria-label","Appearance");
const modes=[["auto","◐"],["light","☀"],["dark","☾"]];s.innerHTML=modes.map(([m,i])=>`<button data-m="${m}" title="${m[0].toUpperCase()+m.slice(1)} appearance" aria-label="${m} appearance">${i}</button>`).join("");ctl.prepend(s);
const set=m=>{if(m==="auto")document.documentElement.removeAttribute("data-theme");else document.documentElement.dataset.theme=m;localStorage.setItem("v28theme",m);s.querySelectorAll("button").forEach(b=>b.classList.toggle("on",b.dataset.m===m));window.dispatchEvent(new Event("resize"))};
s.onclick=e=>{const b=e.target.closest("button");if(b)set(b.dataset.m)};set(localStorage.getItem("v28theme")||"auto")})();
// count-up numbers + skeletons for every big number on the page
const nre=/^([^\d-]*)(-?[\d,]*\.?\d+)(.*)$/s,anim=new WeakMap();
function countUp(el){if(el.dataset.v28busy)return;const t=el.textContent.trim();if(t==="–"||t===""){el.classList.add("v28sk");return}el.classList.remove("v28sk");
const m=t.match(nre);const prev=anim.get(el);anim.set(el,t);if(calm||document.hidden||!m||!prev||/\d/.test(m[3])||el.id==="ver")return;const pm=prev.match(nre);if(!pm||pm[1]!==m[1]||pm[3]!==m[3])return;
const a=parseFloat(pm[2].replace(/,/g,"")),b=parseFloat(m[2].replace(/,/g,""));if(!isFinite(a)||!isFinite(b)||a===b||Math.abs(b-a)<1e-9)return;const dec=(m[2].split(".")[1]||"").length,comma=m[2].includes(",")||Math.abs(b)>=1e4&&pm[2].includes(",");
const t0=performance.now(),D=520;el.dataset.v28busy=1;const step=now=>{const k=Math.min(1,(now-t0)/D),e=1-Math.pow(1-k,3),v=a+(b-a)*e;el.textContent=m[1]+(comma?v.toLocaleString(undefined,{minimumFractionDigits:dec,maximumFractionDigits:dec}):v.toFixed(dec))+m[3];if(k<1)requestAnimationFrame(step);else{el.textContent=t;delete el.dataset.v28busy}};requestAnimationFrame(step)}
const mo=new MutationObserver(ms=>{for(const r of ms){const el=r.target.nodeType===3?r.target.parentElement:r.target;if(el&&el.matches&&el.matches(".big,.v27big,.v28big")&&!el.dataset.v28busy)countUp(el)}});
const watchNums=()=>document.querySelectorAll(".big,.v27big,.v28big").forEach(el=>{if(!el.dataset.v28w){el.dataset.v28w=1;countUp(el);mo.observe(el,{childList:true,characterData:true,subtree:true})}});
// entrance: cards rise in once, staggered
const io="IntersectionObserver"in window?new IntersectionObserver(es=>{let i=0;for(const e of es)if(e.isIntersecting){const el=e.target;el.style.animationDelay=Math.min(i++*40,240)+"ms";el.classList.add("v28in");io.unobserve(el)}},{rootMargin:"0px 0px -5% 0px"}):null;
const watchCards=()=>{if(calm||!io)return;document.querySelectorAll(".card:not([data-v28c])").forEach(c=>{c.dataset.v28c=1;io.observe(c)})};
// Dashboard <-> Version tab transition
// Watches only hidden->visible flips and animates with the Web Animations API, never touching
// the class attribute it observes (2.8.0 re-added a class here and looped forever: Version tab froze).
const paneIn=p=>{let shown=!p.classList.contains("hidden");new MutationObserver(()=>{const now=!p.classList.contains("hidden");if(now&&!shown&&!calm&&p.animate)p.animate([{opacity:0,transform:"translateY(6px)"},{opacity:1,transform:"none"}],{duration:380,easing:"cubic-bezier(.2,.8,.2,1)"});shown=now}).observe(p,{attributes:true,attributeFilter:["class"]})};
const panesWatch=()=>["dpane","vpane","devpane","advpane"].forEach(id=>{const p=$(id);if(p&&!p.dataset.v28p){p.dataset.v28p=1;paneIn(p)}});panesWatch();setTimeout(panesWatch,1500);
// shared tooltip
const tip=document.createElement("div");tip.className="v28tip";document.body.appendChild(tip);
const showTip=(x,y,html)=>{tip.innerHTML=html;tip.classList.add("on");const w=tip.offsetWidth,h=tip.offsetHeight;tip.style.left=Math.min(innerWidth-w-8,Math.max(8,x+14))+"px";tip.style.top=Math.max(8,y-h-12)+"px"},hideTip=()=>tip.classList.remove("on");
// ---------- canvas helpers (same as the Live graph) ----------
const pr=document.createElement("i");pr.style.display="none";document.body.appendChild(pr);
const col=v=>{pr.style.color=v;const c=getComputedStyle(pr).color;pr.style.color="";return c},rgba=(c,a)=>c.replace(/^rgba?\(([^,]+),([^,]+),([^,)]+).*$/,`rgba($1,$2,$3,${a})`);
function curve(g,P){const n=P.length;if(!n)return;g.moveTo(P[0][0],P[0][1]);if(n<3){for(const p of P)g.lineTo(p[0],p[1]);return}
const d=[],m=[];for(let i=0;i<n-1;i++){const dx=P[i+1][0]-P[i][0];d.push(dx?(P[i+1][1]-P[i][1])/dx:0)}
m[0]=d[0];m[n-1]=d[n-2];for(let i=1;i<n-1;i++)m[i]=d[i-1]*d[i]<=0?0:(d[i-1]+d[i])/2;
for(let i=0;i<n-1;i++){if(!d[i]){m[i]=m[i+1]=0;continue}const a=m[i]/d[i],b=m[i+1]/d[i],h=a*a+b*b;if(h>9){const t=3/Math.sqrt(h);m[i]=t*a*d[i];m[i+1]=t*b*d[i]}}
for(let i=0;i<n-1;i++){const dx=(P[i+1][0]-P[i][0])/3;g.bezierCurveTo(P[i][0]+dx,P[i][1]+m[i]*dx,P[i+1][0]-dx,P[i+1][1]-m[i+1]*dx,P[i+1][0],P[i+1][1])}}
function ctx(c){const dpr=devicePixelRatio||1,W=c.clientWidth,H=c.clientHeight;if(!W)return null;if(c.width!==Math.round(W*dpr)||c.height!==Math.round(H*dpr)){c.width=Math.round(W*dpr);c.height=Math.round(H*dpr)}const g=c.getContext("2d");g.setTransform(dpr,0,0,dpr,0,0);g.clearRect(0,0,W,H);g.font="11px -apple-system,system-ui,sans-serif";g.lineJoin="round";g.lineCap="round";return{g,W,H}}
function area(g,P,c,top,bot,lw,fill){if(P.length<2)return;if(fill){const gr=g.createLinearGradient(0,top,0,bot);gr.addColorStop(0,rgba(c,.26));gr.addColorStop(1,rgba(c,0));g.fillStyle=gr;g.beginPath();curve(g,P);g.lineTo(P[P.length-1][0],bot);g.lineTo(P[0][0],bot);g.closePath();g.fill()}g.strokeStyle=c;g.lineWidth=lw;g.beginPath();curve(g,P);g.stroke()}
function grid(g,W,top,h){g.strokeStyle=col("var(--faint)");g.lineWidth=1;g.globalAlpha=.2;g.setLineDash([2,4]);g.beginPath();for(const f of[0,.25,.5,.75])g.moveTo(0,Math.round(top+f*h)+.5),g.lineTo(W,Math.round(top+f*h)+.5);g.stroke();g.setLineDash([]);g.globalAlpha=.35;g.beginPath();g.moveTo(0,top+h+.5);g.lineTo(W,top+h+.5);g.stroke();g.globalAlpha=1}
// draw-in: reveal a chart left-to-right with a clip (one 700 ms animation per data load)
function drawIn(draw){if(calm){draw(1);return}const t0=performance.now();const f=t=>{const k=Math.min(1,(t-t0)/700);draw(1-Math.pow(1-k,3));if(k<1)requestAnimationFrame(f)};requestAnimationFrame(f)}
function spark(c,vals,color){const o=ctx(c);if(!o||vals.length<2)return;const{g,W,H}=o,mx=Math.max(...vals,1e-9),mn=Math.min(...vals,0),P=vals.map((v,i)=>[2+i*(W-4)/(vals.length-1),H-3-(v-mn)/(mx-mn||1)*(H-8)]);const cc=col(color);area(g,P,cc,0,H,1.6,true);const L=P[P.length-1];g.fillStyle=cc;g.beginPath();g.arc(L[0],L[1],2.6,0,7);g.fill()}
// Activity-style ring (SVG, animated with a spring via CSS transition)
const ring=(r,w,v,c)=>{const C=2*Math.PI*r;return`<circle r="${r}" cx="60" cy="60" fill="none" stroke="color-mix(in srgb,${c} 18%,transparent)" stroke-width="${w}"/><circle r="${r}" cx="60" cy="60" fill="none" stroke="${c}" stroke-width="${w}" stroke-linecap="round" stroke-dasharray="0 ${C}" data-to="${Math.max(.001,Math.min(1,v))*C} ${C}" style="transition:stroke-dasharray 1.1s var(--spring)"/>`};
const growRings=el=>requestAnimationFrame(()=>requestAnimationFrame(()=>el.querySelectorAll("[data-to]").forEach(c=>c.setAttribute("stroke-dasharray",c.dataset.to))));
// ---------- layout ----------
const dp=$("dpane");if(!dp)return;
const hd=(t,h,c,extra)=>`<div class="hd"><div class="lbl"><i style="width:8px;height:8px;border-radius:50%;background:${c};display:inline-block"></i>${t} <button class="q" data-h="${h}">?</button></div>${extra||""}</div>`;
const sm=document.createElement("div");sm.id="v28";
sm.innerHTML=`<div class="v28kpis" id="v28kpis"></div>
<div class="v28g"><section class="card" id="v28sp" style="grid-column:1/-1">${hd("Speed history","v28speed","var(--accent)",`<span class="seg" id="v28rg">${["1h","24h","7d","30d"].map(r=>`<button data-r="${r}">${r}</button>`).join("")}</span>`)}
<div class="legend" style="margin-bottom:6px"><span><i style="background:var(--accent)"></i>Uncached avg</span><span><i style="background:var(--purple)"></i>p95 (all)</span><span><i style="background:var(--green)"></i>Cache share</span></div>
<canvas id="v28spc" style="height:260px" role="img" aria-label="Speed history"></canvas></section></div>
<div class="v28g"><section class="card" id="v28up">${hd("Smart upstreams","v28smart","var(--green)",`<span class="small" id="v28ups"></span>`)}<div id="v28upl"><div class="v28empty"><span class="v28sk" style="width:60%;height:14px"></span></div></div></section>
<section class="card" id="v28rp">${hd("Weekly report card","v28report","var(--purple)",`<span class="small" id="v28rps"></span>`)}<div id="v28rpb"><div class="v28empty"><span class="v28sk" style="width:60%;height:14px"></span></div></div></section></div>
<div class="v28g"><section class="card" id="v28hb">${hd("Habits · hour of week","v28habit","var(--amber)",`<span class="small" id="v28hbs"></span>`)}<canvas id="v28hbc" style="height:190px" role="img" aria-label="Busy hours of the week"></canvas></section>
<section class="card" id="v28ev">${hd("Self-healing &amp; security","v28events","var(--red)",`<span class="small" id="v28evs"></span>`)}<div id="v28evl" style="max-height:260px;overflow:auto"></div></section></div>
<section class="card" id="v28st" style="margin-bottom:16px">${hd("Smart settings","v28set","var(--purple)",`<span class="small" id="v28msg"></span>`)}<div id="v28form" class="small">Loading…</div></section>`;
const anchor=$("v27")||$("health");anchor?anchor.after(sm):dp.prepend(sm);
// section nav (Linear-style sticky segmented control with a sliding spring indicator)
const nav=document.createElement("nav");nav.className="v28nav";nav.setAttribute("aria-label","Sections");
const secs=[["Overview","health"],["Smart","v28"],["Speed","v28sp"],["Security","v28ev"],["Report","v28rp"],["Settings","v28st"],["Log","log"]].filter(([,id])=>$(id));
nav.innerHTML="<i></i>"+secs.map(([t,id])=>`<button data-s="${id}">${t}</button>`).join("");dp.prepend(nav);const ind=nav.querySelector("i");
const mark=id=>{nav.querySelectorAll("button").forEach(b=>{const on=b.dataset.s===id;b.classList.toggle("on",on);if(on){ind.style.left=b.offsetLeft+"px";ind.style.width=b.offsetWidth+"px"}})};
nav.onclick=e=>{const b=e.target.closest("button");if(!b)return;const el=$(b.dataset.s),sec=el.closest("section")||el;mark(b.dataset.s);scrollTo({top:sec.getBoundingClientRect().top+scrollY-120,behavior:calm?"auto":"smooth"})};
const hdr=document.querySelector("header");const topFix=()=>{if(hdr)document.documentElement.style.setProperty("--v28top",(getComputedStyle(hdr).position==="sticky"?hdr.offsetHeight+8:6)+"px")};topFix();addEventListener("resize",topFix);
let navT=0;addEventListener("scroll",()=>{if(navT)return;navT=setTimeout(()=>{navT=0;let cur=secs[0][1];for(const[,id]of secs){const el=$(id),s=el.closest("section")||el;if(s.getBoundingClientRect().top<180)cur=id}mark(cur)},120)},{passive:true});requestAnimationFrame(()=>mark(secs[0][1]));
// ---------- KPI tiles + speed chart ----------
let rg=localStorage.getItem("v28rg")||"24h",series=null;
const setRg=r=>{rg=r;localStorage.setItem("v28rg",r);$("v28rg").querySelectorAll("button").forEach(b=>b.classList.toggle("on",b.dataset.r===r))};
$("v28rg").onclick=e=>{const b=e.target.closest("button");if(b){setRg(b.dataset.r);loadSeries(true)}};setRg(rg);
function delta(cur,prev,goodUp,isPct){if(prev==null||!isFinite(prev)||!prev)return`<span class="v28d flat" title="nothing to compare with yet">${cur?"new":"–"}</span>`;let d=isPct?100*(cur-prev):prev?100*(cur-prev)/prev:100;
if(Math.abs(d)<.5)return`<span class="v28d flat" title="vs previous ${rg}">±0${isPct?" pt":"%"}</span>`;const good=(d>0)===goodUp;return`<span class="v28d ${good?"good":"bad"}" title="vs previous ${rg}">${d>0?"▲":"▼"} ${Math.abs(d).toFixed(Math.abs(d)<10?1:0)}${isPct?" pt":"%"}</span>`}
function kpis(j){const T=j.total,P=j.prev_total,pts=j.points||[];const fails=p=>p.q?p.failed/p.q:0;
const K=[["Lookups",fmt(T.q),delta(T.q,P.q,true),pts.map(p=>p.q),"var(--accent)"],["Cache share",pct(j.hit_rate),delta(j.hit_rate,j.prev_hit_rate,true,true),pts.map(p=>{const d=p.cached+p.fwd+p.stale;return d?(p.cached+p.stale)/d:0}),"var(--green)"],
["Uncached avg",ms(T.fwd_avg_ms),delta(T.fwd_avg_ms,P.fwd_avg_ms,false),pts.map(p=>p.fwd_avg_ms||0),"var(--accent)"],["p95 answer",j.p95_ms?"≤"+ms(j.p95_ms):"–",delta(j.p95_ms,j.prev_p95_ms,false),pts.map(p=>p.q),"var(--purple)"],
["Failed",fmt(T.failed),delta(T.failed,P.failed,false),pts.map(fails),"var(--red)"],["Threats / flagged",fmt(T.threat+T.flagged),"",pts.map(p=>p.threat+p.flagged),"var(--amber)"],["Devices (peak)",fmt(T.clients),"",pts.map(p=>p.clients),"#14b8a6"]];
const el=$("v28kpis");if(!el.children.length)el.innerHTML=K.map((k,i)=>`<div class="card" style="padding:14px 16px"><div class="v28k">${k[0]}${i==0?' <button class="q" data-h="v28kpi">?</button>':""}</div><div><span class="v28big" id="v28kv${i}">–</span><span id="v28kd${i}"></span></div><canvas class="v28spark" id="v28ks${i}" role="img" aria-label="${k[0]} trend"></canvas></div>`).join("");
K.forEach((k,i)=>{$("v28kv"+i).textContent=k[1];$("v28kd"+i).innerHTML=k[2];spark($("v28ks"+i),k[3].length>1?k[3]:[0,0],k[4])});watchNums();watchCards()}
let spHover=-1;
function drawSpeed(prog){const c=$("v28spc"),o=ctx(c);if(!o||!series)return;const{g,W,H}=o,top=10,h=H-30,pts=series.points||[];grid(g,W,top,h);
if(pts.length<2){g.fillStyle=col("var(--muted)");g.textAlign="center";g.fillText(pts.length?"Collecting… one point so far":"No history yet — it fills in minute by minute",W/2,top+h/2);g.textAlign="start";return}
const t0=series.from,t1=series.to,x=t=>(t-t0)/(t1-t0)*(W-8)+4,mx=Math.max(5,...pts.map(p=>Math.max(p.fwd_avg_ms||0,hp95(p))))*1.15,y=v=>top+h-Math.min(v/mx,1)*h,hit=p=>{const d=p.cached+p.fwd+p.stale;return d?(p.cached+p.stale)/d:null};
g.save();g.beginPath();g.rect(0,0,W*prog,H);g.clip();
area(g,pts.filter(p=>hit(p)!=null).map(p=>[x(p.t),top+h-hit(p)*h]),col("var(--green)"),top,top+h,1.4,true);
area(g,pts.map(p=>[x(p.t),y(hp95(p))]),col("var(--purple)"),top,top+h,1.4,false);
area(g,pts.filter(p=>p.fwd).map(p=>[x(p.t),y(p.fwd_avg_ms)]),col("var(--accent)"),top,top+h,2.2,true);g.restore();
g.fillStyle=col("var(--muted)");g.globalAlpha=.65;g.fillText(ms(mx/1.15),4,top+10);const ts=t=>{const d=new Date(t*1e3);return rg==="1h"||rg==="24h"?d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}):d.toLocaleDateString([],{month:"short",day:"numeric"})};
g.fillText(ts(t0),4,H-4);g.fillText("now",W-26,H-4);g.textAlign="center";g.fillText(ts((t0+t1)/2),W/2,H-4);g.textAlign="start";g.globalAlpha=1;
if(spHover>=0&&pts[spHover]){const p=pts[spHover],X=x(p.t);g.strokeStyle=col("var(--text)");g.globalAlpha=.3;g.beginPath();g.moveTo(X+.5,top);g.lineTo(X+.5,top+h);g.stroke();g.globalAlpha=1;for(const[v,cc]of[[p.fwd?p.fwd_avg_ms:null,"var(--accent)"],[hp95(p),"var(--purple)"]])if(v!=null){g.fillStyle=col(cc);g.beginPath();g.arc(X,y(v),3.5,0,7);g.fill()}}
if(window.GP281)GP281.markers(g,x,top,h,t0,t1,prog)}
const BB=[.1,.5,1,5,10,25,50,100,250,1000,2000];function hp95(p){const hs=p.hist||[],n=hs.reduce((a,b)=>a+b,0);if(!n)return 0;let a=0;for(let i=0;i<11;i++){a+=hs[i];if(a>=n*.95)return BB[i]}return 2000}
$("v28spc").addEventListener("mousemove",e=>{if(!series)return;const r=e.target.getBoundingClientRect(),pts=series.points||[];if(!pts.length)return;const t=series.from+(e.clientX-r.left-4)/(r.width-8)*(series.to-series.from);let bi=0,bd=1e18;pts.forEach((p,i)=>{const d=Math.abs(p.t-t);if(d<bd){bd=d;bi=i}});spHover=bi;drawSpeed(1);const p=pts[bi],d=p.cached+p.fwd+p.stale;
showTip(e.clientX,e.clientY,`<div class="small">${new Date(p.t*1e3).toLocaleString([],{weekday:"short",hour:"2-digit",minute:"2-digit"})}</div><b>${fmt(p.q)}</b> lookups · <b>${d?pct((p.cached+p.stale)/d):"–"}</b> cached<br>uncached <b>${ms(p.fwd_avg_ms)}</b> · p95 <b>≤${ms(hp95(p))}</b>${p.failed?`<br><span style="color:var(--red)">${fmt(p.failed)} failed</span>`:""}`)});
$("v28spc").addEventListener("mouseleave",()=>{spHover=-1;hideTip();drawSpeed(1)});
window.GP281redraw=()=>drawSpeed(1);async function loadSeries(anim){if(document.hidden)return;try{series=await api("/api/v28/series?range="+rg);kpis(series);anim?drawIn(drawSpeed):drawSpeed(1)}catch(e){}}
// ---------- smart upstreams ----------
function upsHTML(s){const U=s.upstreams||[];if(!U.length)return`<div class="v28empty"><div><b>◌</b>No upstreams yet</div></div>`;const mx=Math.max(20,...U.map(u=>u.probe_ms||0));
return U.map(u=>{const st=u.breaker?["down","Down"]:u.demoted?["bench","Benched "+Math.ceil(u.demote_sec/60)+" min"]:u.raced?["race","Racing"]:["stand","Standby"];const sc=u.success>=.98?"var(--green)":u.success>=.9?"var(--amber)":"var(--red)";
return`<div class="v28up"><div class="v28rk">${u.rank}</div><div style="min-width:0"><div class="trunc" style="font-weight:550">${esc(u.label||u.name)}<span class="small"> ${esc(u.kind)}</span><span class="v28pill ${st[0]}">${st[1]}</span></div>
<div class="v28meter" title="probe time"><i style="width:${u.probe_ms?Math.max(3,100*u.probe_ms/mx):0}%;background:linear-gradient(90deg,${u.raced?"var(--green)":"var(--faint)"},color-mix(in srgb,${u.raced?"var(--green)":"var(--faint)"} 40%,transparent))"></i></div>
<div class="small" style="margin-top:3px">success <b style="color:${sc}">${pct(u.success)}</b> · wins ${pct(u.win_rate)} (${fmt(u.wins)})</div></div><div style="text-align:right"><div class="v28big" style="font-size:20px">${u.probe_ms?ms(u.probe_ms):"–"}</div><div class="small">probe</div></div></div>`}).join("")}
// ---------- habits heat grid ----------
let hab=null,hbHover=-1;const DAYS=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
function drawHab(prog){const c=$("v28hbc"),o=ctx(c);if(!o||!hab)return;const{g,W,H}=o,L=30,cw=(W-L)/24,rh=(H-16)/7,mx=Math.max(1,...hab.heat),a=col("var(--amber)");
g.fillStyle=col("var(--muted)");g.globalAlpha=.7;DAYS.forEach((d,i)=>g.fillText(d,0,i*rh+rh/2+4));for(const hh of[0,6,12,18])g.fillText(String(hh).padStart(2,"0"),L+hh*cw,H-2);g.globalAlpha=1;
for(let i=0;i<168;i++){const d=Math.floor(i/24),hh=i%24,v=hab.heat[i]/mx,k=Math.pow(v,.5)*prog;g.fillStyle=v?rgba(a,(.1+.85*k).toFixed(3)):rgba(col("var(--faint)"),.12);const x=L+hh*cw,y=d*rh;g.beginPath();g.roundRect?g.roundRect(x+1,y+1,cw-2,rh-2,Math.min(4,cw/4)):g.rect(x+1,y+1,cw-2,rh-2);g.fill();
if(i===hab.now){g.strokeStyle=col("var(--text)");g.globalAlpha=.6;g.lineWidth=1.5;g.stroke();g.globalAlpha=1}if(i===hbHover){g.strokeStyle=col("var(--accent)");g.lineWidth=2;g.stroke()}}}
$("v28hbc").addEventListener("mousemove",e=>{if(!hab)return;const r=e.target.getBoundingClientRect(),L=30,cw=(r.width-L)/24,rh=(r.height-16)/7,hh=Math.floor((e.clientX-r.left-L)/cw),d=Math.floor((e.clientY-r.top)/rh);if(hh<0||hh>23||d<0||d>6){hbHover=-1;hideTip();drawHab(1);return}const i=d*24+hh;hbHover=i;drawHab(1);
const t=hab.top[i]||[];showTip(e.clientX,e.clientY,`<b>${DAYS[d]} ${String(hh).padStart(2,"0")}:00</b>${i===hab.now?' · <span style="color:var(--green)">now</span>':""}<br>${t.length?t.map(esc).join("<br>"):'<span class="small">nothing learned yet</span>'}`)});
$("v28hbc").addEventListener("mouseleave",()=>{hbHover=-1;hideTip();drawHab(1)});
// ---------- events ----------
function evHTML(s){const E=[...(s.heal.events||[]).map(e=>({t:e.t,c:e.kind==="recovered"?"var(--green)":e.kind==="demote"?"var(--amber)":"var(--accent)",title:{latency:"Got slow",hit_rate:"Cache share dropped",failures:"Lookups failing",demote:"Upstream benched",recovered:"Recovered"}[e.kind]||e.kind,body:e.detail+(e.action&&e.action!=="none"?" → "+e.action:"")})),
...(s.detect.events||[]).map(e=>({t:e.t,c:"var(--red)",title:(e.kind==="dga"?"Random-looking domain":"Possible DNS tunneling")+(s.detect.block?" · blocked":" · alert only"),body:e.domain+" — "+e.reason}))].sort((a,b)=>b.t-a.t).slice(0,60);
if(!E.length)return`<div class="v28empty"><div><b>✓</b>All quiet. Nothing needed fixing and nothing suspicious was seen.</div></div>`;
return E.map(e=>`<div class="v28ev"><i style="background:${e.c}"></i><div><div style="font-weight:550">${esc(e.title)}</div><div class="small" style="white-space:normal">${esc(e.body)}</div></div><span class="small">${new Date(e.t*1e3).toLocaleString([],{weekday:"short",hour:"2-digit",minute:"2-digit"})}</span></div>`).join("")}
// ---------- report card ----------
function reportHTML(r){const T=r.this,P=r.prev;if(!T.q)return`<div class="v28empty"><div><b>◷</b>The first report appears once a few hours of history are saved.</div></div>`;
const hit=r.hit_rate[0],sp=r.p95_ms[0]?Math.max(0,Math.min(1,1-(Math.log10(r.p95_ms[0])-0)/3)):0,rel=T.q?1-T.failed/T.q:1;
const gc={A:"var(--green)",B:"var(--accent)",C:"var(--amber)",D:"var(--red)"}[r.grade]||"var(--muted)";const days=r.days||[],mx=Math.max(1,...days.map(d=>d.q));
return`<div class="v28rings"><div style="position:relative;width:120px;height:120px"><svg width="120" height="120" viewBox="0 0 120 120" style="transform:rotate(-90deg)" role="img" aria-label="Cache ${pct(hit)}, speed, reliability ${pct(rel)}">${ring(52,11,hit,"var(--green)")}${ring(38,11,sp,"var(--accent)")}${ring(24,11,rel,"var(--purple)")}</svg>
<div style="position:absolute;inset:0;display:grid;place-items:center;font:700 22px -apple-system,system-ui;color:${gc}">${esc(r.grade)}</div></div>
<div class="kv" style="flex:1;min-width:170px"><div><i class="dot" style="background:var(--green)"></i>Cache share</div><div>${pct(hit)}${delta(hit,r.hit_rate[1],true,true)}</div><div><i class="dot" style="background:var(--accent)"></i>p95 answer</div><div>≤${ms(r.p95_ms[0])}${delta(r.p95_ms[0],r.p95_ms[1],false)}</div>
<div><i class="dot" style="background:var(--purple)"></i>Answered</div><div>${pct(rel)}</div><div>Lookups</div><div>${fmt(T.q)}${delta(T.q,P.q,true)}</div><div>Uncached avg</div><div>${ms(T.fwd_avg_ms)}</div></div></div>
<div style="display:flex;align-items:flex-end;gap:6px;height:70px;margin:14px 0 4px">${days.map(d=>`<div style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%" title="${fmt(d.q)} lookups"><span style="width:100%;max-width:34px;border-radius:5px 5px 2px 2px;background:linear-gradient(180deg,var(--purple),color-mix(in srgb,var(--purple) 35%,transparent));height:${Math.max(3,100*d.q/mx)}%;transition:height .8s var(--spring)"></span><em class="small" style="font-style:normal;margin-top:3px">${new Date(d.t*1e3).toLocaleDateString([],{weekday:"short"})}</em></div>`).join("")}</div>
${(r.top_domains||[]).length?`<div class="v28k" style="margin-top:12px">Top domains</div><div class="chips" style="margin-top:6px">${r.top_domains.slice(0,8).map(t=>`<span class="chip">${esc(t.host)} <span class="small">${fmt(t.requests)}</span></span>`).join("")}</div>`:""}
<div class="v28k" style="margin-top:12px">Worth knowing</div>${(r.anomalies||[]).length?r.anomalies.map(a=>`<div class="small" style="padding:3px 0">• ${esc(a)}</div>`).join(""):`<div class="small" style="padding:3px 0;color:var(--green)">✓ Nothing unusual this week</div>`}`}
// ---------- settings ----------
let cfg=null,stat=null;
const tog=(id,on)=>`<button class="tog${on?" on":""}" id="${id}" role="switch" aria-checked="${!!on}"></button>`;
function form(){const c=cfg,s=stat;const row=(t,sub,ctl)=>`<div class="v28f"><div><div style="font-weight:550;color:var(--text)">${t}</div><div class="small">${sub}</div></div>${ctl}</div>`;
$("v28form").innerHTML=`<div class="v28g" style="margin:0"><div>`+
row("Smart upstreams",`Race the best ${c.smart_n||3} of ${(s.smart.upstreams||[]).length}; probe all every minute`,tog("v28_smart",!c.smart_off))+row("Race size","Upstreams raced per lookup (1–16)",`<input type="number" id="v28_n" min="1" max="16" value="${c.smart_n||3}">`)+
row("Prefetch",`Refresh popular answers before they expire · ${fmt(s.prefetch.done)} done`,tog("v28_pf",!c.prefetch_off))+row("Prefetch limit","Per second",`<input type="number" id="v28_pr" min="1" max="500" value="${c.prefetch_rate||20}">`)+
row("Habit pre-warm",`Totals only, no device data · ${fmt(s.habits.warmed)} warmed`,tog("v28_hb",!c.habits_off))+row("Self-healing","Bench upstreams, widen the race, re-warm; alerts use your webhook if on",tog("v28_heal",!c.heal_off))+
row("Warm connections",`Keep encrypted upstream connections open with a tiny query every 15 s · ${fmt(((s.speed||{}).upstreams||[]).reduce((a,u)=>a+u.warms,0))} sent`,tog("v28_warm",!c.warm_off))+
row("Serve stale at once",`RFC 8767: answer expired names instantly (TTL 30 s), refresh in the background · kept up to 1 day`,tog("v28_stale",!c.serve_stale_off))+
row("Nearest anycast address",`Use the provider's faster sibling address when measured ≥20% quicker · ${((s.speed||{}).anycast_picks||[]).length} switched`,tog("v28_any",!c.anycast_off))+
row("HTTP/3 (QUIC) for DoH",`Experimental; falls back to HTTP/2 per server · ${c.h3_on?((s.speed||{}).upstreams||[]).filter(u=>u.h3==="in use").length+" using HTTP/3":"off"}`,tog("v28_h3",c.h3_on))+
row("Adaptive TTL",`Stable answers kept up to 2× (max 1 h); never under 60 s · ${fmt(s.ttl.extended)} stretched, ${fmt(s.ttl.shortened)} shortened`,tog("v28_ttl",!c.adaptive_ttl_off))+`</div><div>`+
row("Suspicious-domain detection",`Random-looking names and DNS tunneling · ${fmt(s.detect.dga)} DGA, ${fmt(s.detect.tunnel)} tunnel`,tog("v28_det",!c.detect_off))+row("Block suspicious domains","Off = alert only",tog("v28_detb",c.detect_block))+
row("Threat feeds",`Phishing &amp; malware sinkhole · ${s.threat.size?fmt(s.threat.size)+" names":"not downloaded"}${s.threat.updating?" · updating…":""}`,tog("v28_th",c.threat_on))+
`<div class="small" style="margin-top:4px">Feeds (one URL per line; empty = URLhaus + Phishing Army)</div><textarea class="v28ta" id="v28_tl" placeholder="${esc((s.default_threat_lists||[]).join("\n"))}">${esc((c.threat_lists||[]).join("\n"))}</textarea>`+
row("DNSSEC strict",`Your upstreams validate DNSSEC; strict keeps a bad signature an error instead of retrying with CD=1 · ${fmt(s.dnssec.passthrough)} passed through so far`,tog("v28_ds",c.dnssec_strict))+
`<div class="small" style="margin-top:10px">History file: ${(s.tsdb.bytes/1048576).toFixed(1)} of ${(s.tsdb.max_bytes/1048576).toFixed(1)} MB (${s.tsdb.days} days)</div></div></div>
<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px"><button class="btn" id="v28save" style="background:var(--accent);color:#fff">Save</button></div>`;
$("v28form").querySelectorAll(".tog").forEach(b=>b.onclick=()=>{b.classList.toggle("on");b.setAttribute("aria-checked",b.classList.contains("on"))});
$("v28save").onclick=async()=>{const on=id=>$(id).classList.contains("on");const n={smart_off:!on("v28_smart"),smart_n:+$("v28_n").value||0,prefetch_off:!on("v28_pf"),prefetch_rate:+$("v28_pr").value||0,habits_off:!on("v28_hb"),heal_off:!on("v28_heal"),adaptive_ttl_off:!on("v28_ttl"),
detect_off:!on("v28_det"),detect_block:on("v28_detb"),threat_on:on("v28_th"),threat_lists:$("v28_tl").value.split(/\s+/).filter(Boolean),dnssec_strict:on("v28_ds"),warm_off:!on("v28_warm"),serve_stale_off:!on("v28_stale"),anycast_off:!on("v28_any"),h3_on:on("v28_h3")};
const m=$("v28msg");try{await post("/api/v28/config",n);m.textContent="Saved ✓";m.style.color="var(--green)";cfgDirty=false;loadStatus(true)}catch(e){m.textContent=e.message;m.style.color="var(--red)"}setTimeout(()=>m.textContent="",4000)}}
let cfgDirty=false;$("v28form").addEventListener("input",()=>cfgDirty=true);$("v28form").addEventListener("click",e=>{if(e.target.classList.contains("tog"))cfgDirty=true});
async function loadStatus(force){if(document.hidden&&!force)return;try{const s=await api("/api/v28/status");stat=s;const sm=s.smart,U=sm.upstreams||[];
$("v28ups").textContent=sm.on?(sm.widened?"self-healing: racing all "+U.length:`racing ${Math.min(sm.n,U.length)} of ${U.length}`):"off · racing all";$("v28upl").innerHTML=upsHTML(sm);
const firstHab=!hab;hab=s.habits;const learned=hab.heat.filter(v=>v>0).length;$("v28hbs").textContent=hab.on?(learned?learned+" of 168 hours learned":"learning…"):"off";firstHab?drawIn(drawHab):drawHab(1);
$("v28evl").innerHTML=evHTML(s);$("v28evs").textContent=s.detect.block?"blocking suspicious":"alert only";if(!cfgDirty||force){cfg=s.config||{};form()}watchCards()}catch(e){$("v28upl").innerHTML=`<div class="v28empty">${esc(e.message)}</div>`}}
async function loadReport(){if(document.hidden)return;try{const r=await api("/api/v28/report");$("v28rps").textContent=new Date(r.from*1e3).toLocaleDateString([],{month:"short",day:"numeric"})+" – today";$("v28rpb").innerHTML=reportHTML(r);growRings($("v28rpb"))}catch(e){}}
// ---------- schedule (light: 3 small requests, slower when the tab is hidden) ----------
loadSeries(true);loadStatus();loadReport();watchNums();watchCards();
setInterval(()=>loadSeries(false),30000);setInterval(()=>loadStatus(false),10000);setInterval(loadReport,300000);setInterval(()=>{watchNums();watchCards()},3000);
document.addEventListener("visibilitychange",()=>{if(!document.hidden){loadSeries(false);loadStatus(false)}});
let rz=0;addEventListener("resize",()=>{clearTimeout(rz);rz=setTimeout(()=>{drawSpeed(1);drawHab(1);if(series)kpis(series)},120)});
})();
