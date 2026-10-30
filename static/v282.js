// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
// GoProxy DNS v2.8.2: Devices (per-device lookups), Health & stability card, .home names,
// phone-first layout (bottom tab bar), customizable card layout, skeletons, empty states,
// plain-English tooltips, focus rings, smooth crossfades (reduced-motion aware).
// Inspirations: UniFi client list (per-device usage + sparkline), Apple Home/iOS tab bar and
// edit-mode "jiggle" reorder, Linear skeletons, Vercel empty states, Stripe tooltips.
(()=>{"use strict";
const $=id=>document.getElementById(id),esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const RM=matchMedia("(prefers-reduced-motion: reduce)");
const api=async u=>{const r=await fetch(u,{cache:"no-store"});if(!r.ok)throw new Error(r.statusText);return r.json()};
const fmt=n=>Number(n||0).toLocaleString(),ms=v=>!v?"–":v<10?v.toFixed(1)+" ms":Math.round(v)+" ms";
const ago=t=>{if(!t)return"never";const s=Date.now()/1e3-t;return s<90?"just now":s<5400?Math.round(s/60)+" min ago":s<129600?Math.round(s/3600)+" h ago":Math.round(s/86400)+" days ago"};
const dur=s=>s<3600?Math.round(s/60)+" min":s<172800?Math.round(s/3600)+" h":Math.round(s/86400)+" days";
const H=window.HELP||(window.HELP={});
H.gpdev=["Devices","Every phone, computer and gadget that used this DNS server, with how many lookups it made, its favourite sites, how many were blocked or failed, and how fast it was answered. Counts are kept only on this server (never sent anywhere) and capped at 256 devices.","Your busiest device at the top."];
H.gpstab=["Health & stability","Shows that the server is answering, how many saved answers it brought back after its last restart, when your data was last backed up, and whether the watchdog had to step in.","All green."];
H.gphome=["Home names",".home names let you type nas.home instead of 192.168.1.20. Names you add in Settings › Local names always win; the rest are learned automatically from your router (read-only).","nas.home, printer.home"];
const css=document.createElement("style");css.textContent=`
:root{--gp-r:16px;--gp-gap:16px}
:focus-visible{outline:2px solid var(--accent)!important;outline-offset:2px;border-radius:8px}
button:not(.q),.btn,select,input{min-height:34px}
.gpsk{display:block;height:14px;margin:9px 0;border-radius:7px;background:linear-gradient(90deg,var(--surface2) 0%,color-mix(in srgb,var(--surface2) 40%,var(--surface)) 50%,var(--surface2) 100%);background-size:200% 100%;animation:gpsk 1.3s ease-in-out infinite}
.gpsk.w6{width:60%}.gpsk.w8{width:80%}.gpsk.w4{width:40%}
@keyframes gpsk{from{background-position:100% 0}to{background-position:-100% 0}}
.gpe{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center;padding:24px 12px;color:var(--muted);font-size:13.5px}.gpe b{font-size:15px;color:var(--text);font-weight:600}.gpe i{font-style:normal;font-size:28px;opacity:.7}
.gpfade{animation:gpfade .32s cubic-bezier(.2,.8,.2,1) both}@keyframes gpfade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
[data-tip]{position:relative;cursor:help}[data-tip]:hover::after,[data-tip]:focus-visible::after{content:attr(data-tip);position:absolute;z-index:40;left:50%;bottom:calc(100% + 8px);transform:translateX(-50%);width:max-content;max-width:240px;padding:8px 10px;border-radius:10px;font-size:12px;font-weight:500;line-height:1.35;letter-spacing:0;text-transform:none;color:var(--text);background:var(--surface);border:1px solid var(--edge);box-shadow:0 8px 24px rgba(0,0,0,.18);white-space:normal;pointer-events:none;animation:gpfade .18s ease both}
.gpst{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.gpst>div{padding:12px 14px;border-radius:14px;background:var(--surface2)}
.gpst .l{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:600}.gpst b{display:block;font-size:20px;font-weight:650;letter-spacing:-.02em;margin-top:2px;font-variant-numeric:tabular-nums}.gpst em{font-style:normal;font-size:12px;color:var(--muted)}
.gpdot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px;background:var(--green);box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 60%,transparent);animation:gppulse 2.2s infinite}.gpdot.warn{background:var(--amber);animation:none}.gpdot.bad{background:var(--red);animation:none}
@keyframes gppulse{70%{box-shadow:0 0 0 8px transparent}100%{box-shadow:0 0 0 0 transparent}}
.gpdv{display:grid;grid-template-columns:34px 1fr auto;gap:2px 12px;align-items:center;padding:9px 4px;border-top:1px solid color-mix(in srgb,var(--edge) 70%,transparent);border-radius:10px;transition:background .2s;cursor:pointer}.gpdv:first-child{border-top:0}.gpdv:hover{background:color-mix(in srgb,var(--surface2) 60%,transparent)}
.gpdv .av{grid-row:span 2;width:34px;height:34px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:15px;background:color-mix(in srgb,var(--accent) 14%,transparent)}
.gpdv .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.gpdv .sub{font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.gpdv .qn{grid-row:span 2;text-align:right;font-variant-numeric:tabular-nums;font-weight:650}
.gpspark{display:flex;align-items:flex-end;gap:2px;height:30px;min-width:96px}.gpspark i{flex:1;min-height:1px;border-radius:2px 2px 0 0;background:var(--accent);opacity:.85;transition:height .7s cubic-bezier(.2,.8,.2,1)}
.gpdd{padding:4px 4px 14px 50px;display:grid;grid-template-columns:1fr 1fr;gap:14px}.gpdd .gpspark{height:56px}@media(max-width:600px){.gpdd{padding-left:4px;grid-template-columns:1fr}}
.gpchip{display:inline-block;font-size:11.5px;font-weight:600;border-radius:999px;padding:2px 8px;margin:0 4px 4px 0;background:var(--surface2);color:var(--muted)}
#gplay{position:fixed;right:18px;bottom:18px;z-index:50;display:none;gap:8px;padding:8px;border-radius:16px;background:var(--surface);border:1px solid var(--edge);box-shadow:0 12px 32px rgba(0,0,0,.2)}body.gpedit #gplay{display:flex}
body.gpedit [data-k]{outline:2px dashed color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:3px;animation:gpjig .5s ease-in-out infinite alternate;cursor:grab}
@keyframes gpjig{from{transform:rotate(-.25deg)}to{transform:rotate(.25deg)}}
.gpctl{display:none;gap:6px;margin-left:auto}body.gpedit .gpctl{display:inline-flex}.gpctl button{min-height:30px;min-width:30px;border-radius:9px;border:1px solid var(--edge);background:var(--surface2);color:var(--text);cursor:pointer;font:inherit}
body.gpedit [data-k].gphid{opacity:.35}body:not(.gpedit) [data-k].gphid{display:none!important}
[data-k].gpdrag{opacity:.5}
#gptab{display:none}
@media(max-width:640px){
 html,body{overflow-x:hidden;max-width:100vw}
 body{padding-bottom:calc(74px + env(safe-area-inset-bottom))}
 #gptab{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:60;justify-content:space-around;padding:6px 6px calc(6px + env(safe-area-inset-bottom));background:color-mix(in srgb,var(--surface) 82%,transparent);backdrop-filter:saturate(1.6) blur(18px);-webkit-backdrop-filter:saturate(1.6) blur(18px);border-top:1px solid var(--edge)}
 #gptab button{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;min-height:52px;border:0;background:none;color:var(--muted);font:inherit;font-size:11px;font-weight:600;border-radius:12px;transition:color .2s,transform .2s}
 #gptab button span{font-size:20px;line-height:1}#gptab button.on{color:var(--accent)}#gptab button:active{transform:scale(.92)}
 .gps-row,.v28g,.gpst{grid-template-columns:1fr!important}
 .gps-kpis{grid-template-columns:1fr 1fr 1fr!important}.gps-k{padding:10px}.gps-k b{font-size:22px!important}
 .card{border-radius:var(--gp-r)}
 .gpscroll,table{max-width:100%;overflow-x:auto;display:block}
 button:not(.q),.btn,select,input{min-height:44px}
 #gplay{left:12px;right:12px;bottom:calc(82px + env(safe-area-inset-bottom));justify-content:center}
}
@media(prefers-reduced-motion:reduce){.gpfade,.gpsk,.gpdot,body.gpedit [data-k],[data-tip]::after{animation:none!important}.gpspark i{transition:none}}
`;document.head.appendChild(css);
const sk=n=>Array.from({length:n},(_,i)=>`<span class="gpsk ${["w8","w6","w4"][i%3]}"></span>`).join("");
const empty=(ic,t,s)=>`<div class="gpe"><i>${ic}</i><b>${esc(t)}</b><span>${esc(s)}</span></div>`;
const icon=n=>{n=(n||"").toLowerCase();return /iphone|ipad|phone|android|pixel|galaxy/.test(n)?"📱":/tv|roku|fire|chromecast|shield/.test(n)?"📺":/nas|synology|server/.test(n)?"🗄️":/mac|pc|laptop|desktop|win/.test(n)?"💻":/cam|tapo|ring|nest/.test(n)?"📷":/echo|alexa|home|speaker|sonos/.test(n)?"🔊":"🔌"};
const spark=(h,big)=>{const m=Math.max(1,...h);return`<div class="gpspark" title="Lookups per hour, last 24 h">${h.map(v=>`<i style="height:${Math.max(3,v/m*100)}%"></i>`).join("")}</div>`};
const devLabel=d=>d.name&&d.name!==d.ip?d.name:(d.home||d.ip);
const devSub=d=>[d.home&&d.home!==devLabel(d)?d.home:"",d.ip!==devLabel(d)?d.ip:"",ms(d.avg_ms)+" avg"].filter(Boolean).join(" · ");
function detail(d){return`<div class="gpdd gpfade"><div><div class="lbl" style="margin-bottom:6px">Last 24 hours</div>${spark(d.hours,1)}<div class="small" style="margin-top:8px">${fmt(d.queries)} lookups · ${d.hit_pct}% from cache · ${fmt(d.blocked)} blocked · ${fmt(d.failed)} failed · last seen ${ago(d.last)}</div></div>
<div><div class="lbl" style="margin-bottom:6px">Top sites</div>${d.top.length?d.top.map(t=>`<span class="gpchip">${esc(t.name)} · ${fmt(t.count)}</span>`).join(""):'<span class="small">No sites yet</span>'}</div></div>`}
function rows(list,expand){return list.map(d=>`<div class="gpdv" data-ip="${esc(d.ip)}" tabindex="0" role="button" aria-expanded="false"><div class="av">${icon(d.name+" "+d.home)}</div><div class="nm">${esc(devLabel(d))}</div><div class="qn" data-tip="Lookups since tracking began">${fmt(d.queries)}<div class="small" style="font-weight:500">${d.blocked?fmt(d.blocked)+" blocked":""}</div></div><div class="sub">${esc(devSub(d))}</div></div>`).join("")}
function bindRows(box,list){box.querySelectorAll(".gpdv").forEach(r=>{const go=async()=>{const n=r.nextElementSibling;if(n&&n.classList.contains("gpdd")){n.remove();r.setAttribute("aria-expanded","false");return}
 r.insertAdjacentHTML("afterend",`<div class="gpdd">${sk(3)}</div>`);r.setAttribute("aria-expanded","true");try{const j=await api("/api/v282/devices?ip="+encodeURIComponent(r.dataset.ip));const d=j.devices[0];r.nextElementSibling.outerHTML=d?detail(d):""}catch(e){r.nextElementSibling.outerHTML=""}};
 r.onclick=go;r.onkeydown=e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();go()}}})}
// ---------- SIMPLE: Top devices + Health & stability (merges "What's happening") ----------
const S=$("gps");
if(S){const live=$("gpslive")?.closest("section");if(live){live.dataset.removed="simple-live";live.remove()} // moved: Pro keeps the full live graph
 const al=$("gpsal"),alSec=al?.closest("section"),row=S.querySelector(".gps-row");
 const r2=document.createElement("div");r2.className="gps-row";r2.innerHTML=`<section class="card" id="gpsdev"><div class="hd"><div class="lbl">Top devices <button class="q" data-h="gpdev">?</button></div><span class="small">busiest first</span></div><div id="gpsdevl">${sk(4)}</div></section>
<section class="card" id="gpsstab"><div class="hd"><div class="lbl">Health &amp; stability <button class="q" data-h="gpstab">?</button></div><span class="small" id="gpsstabs"></span></div><div id="gpsstabb">${sk(3)}</div><div class="lbl" style="margin:14px 0 4px">What's happening</div><div id="gpsalw"></div></section>`;
 row?row.after(r2):S.appendChild(r2);
 if(al&&alSec){$("gpsalw").appendChild(al);alSec.remove()}
 // the 3 hero numbers get plain-English tips
 [["gpsk0","How long a lookup takes on average. Under 5 ms feels instant."],["gpsk1","Share of lookups answered from memory without asking the internet. Higher is faster."],["gpsk2","Ads and trackers stopped before they loaded (only when blocking is on)."]].forEach(([id,t])=>{const e=$(id)?.parentElement;if(e){e.dataset.tip=t;e.tabIndex=0}});
 if(row&&row.children[0]){row.children[0].querySelector(".lbl")?.setAttribute("data-tip","The sites your home looks up most since the server started.")}
 if(row&&!row.children.length)row.remove();
 // fold the old single "Top sites" card into one row with devices for a minimal Simple view
 const ts=$("gpstop")?.closest("section");if(ts&&row&&row!==r2){r2.prepend(ts);row.remove();r2.style.gridTemplateColumns="1fr 1fr";const st=$("gpsstab");st.style.gridColumn="1 / -1"}}
function stabHTML(s){const ops=s.ops||{},b=ops.backup||{},wd=ops.watchdog||{};const bAge=b.t?Date.now()/1e3-b.t:1e12;
 const items=[["Status",`<span class="gpdot"></span>Answering`,`up ${dur(s.uptime_s)}${s.panics?` · ${s.panics} errors caught`:""}`,"The server is running and answering lookups."],
 ["Saved answers restored",fmt(s.cache_restored),s.cache_saved?`saved ${ago(s.cache_saved)}`:"not saved yet","After a restart or update, these answers were loaded from disk so sites stay fast right away. Saved every 10 minutes and on shutdown."],
 ["Last backup",b.t?`<span class="gpdot ${bAge>36*3600?"warn":""}"></span>${ago(b.t)}`:`<span class="gpdot warn"></span>None yet`,b.t?`${b.kept||"?"} kept · ${b.size_mb??"?"} MB`:"runs nightly at 3:15 AM","A copy of the GoProxy and speed-test data, made every night. The last 14 are kept."],
 ["Watchdog",wd.restarts?`${wd.restarts} restart${wd.restarts>1?"s":""}`:"All good",wd.t?`checked ${ago(wd.t)}`:"checks every 2 min","Restarts GoProxy automatically if it stops answering."]];
 return`<div class="gpst gpfade">${items.map(([l,v,e,t])=>`<div data-tip="${esc(t)}" tabindex="0"><div class="l">${l}</div><b>${v}</b><em>${e}</em></div>`).join("")}</div>`}
async function simpleTick(){if(document.hidden||!$("gpsdevl")||document.body.classList.contains("gpp"))return;
 try{const [d,s]=await Promise.all([api("/api/v282/devices"),api("/api/v282/stability")]);const l=d.devices.slice(0,5),box=$("gpsdevl");
  box.innerHTML=l.length?rows(l):empty("🛰️","No devices yet","Devices appear here as soon as they look something up.");bindRows(box,l);
  $("gpsstabb").innerHTML=stabHTML(s);$("gpsstabs").textContent="v"+s.version}catch(e){$("gpsstabb").innerHTML=empty("⚠️","Couldn't load","Retrying in a moment.")}}
// ---------- PRO: Devices explorer + home names ----------
const P=$("gpp");
if(P){const sec=document.createElement("div");sec.className="v28g";sec.innerHTML=`<section class="card" id="gpdev" style="grid-column:1/-1"><div class="hd"><div class="lbl">Devices <button class="q" data-h="gpdev">?</button></div><span class="small" id="gpdevs"></span></div>
<div class="gpbar"><input type="search" id="gpdq" placeholder="Search device, IP, .home name or site" aria-label="Search devices"><select id="gpdo" aria-label="Sort"><option value="queries">Most lookups</option><option value="blocked">Most blocked</option><option value="failed">Most failed</option><option value="avg_ms">Slowest</option><option value="last">Recently seen</option></select></div>
<div class="gpscroll" style="max-height:560px" id="gpdl">${sk(6)}</div></section>
<section class="card" id="gphome"><div class="hd"><div class="lbl">.home names <button class="q" data-h="gphome">?</button></div><span class="small" id="gphs"></span></div><div id="gphl">${sk(3)}</div></section>
<section class="card" id="gpstab"><div class="hd"><div class="lbl">Health &amp; stability <button class="q" data-h="gpstab">?</button></div></div><div id="gppstab">${sk(3)}</div></section>`;
 P.prepend(sec);const nav=document.querySelector(".v28nav");if(nav){const b=document.createElement("button");b.dataset.s="gpdev";b.textContent="Devices";b.className="gpponly";nav.appendChild(b)}}
let dq="",dTimer=0;
async function proDevices(){if(!$("gpdl")||!document.body.classList.contains("gpp")||document.hidden)return;
 try{const [d,s,n]=await Promise.all([api("/api/v282/devices?q="+encodeURIComponent(dq)),api("/api/v282/stability"),api("/api/v282/names")]);const o=$("gpdo").value;
  const l=d.devices.sort((a,b)=>o==="avg_ms"?b.avg_ms-a.avg_ms:(b[o]||0)-(a[o]||0));$("gpdevs").textContent=`${d.tracked} of max ${d.cap} tracked · stored only on this server`;
  const open=[...$("gpdl").querySelectorAll('.gpdv[aria-expanded="true"]')].map(r=>r.dataset.ip);
  $("gpdl").innerHTML=l.length?l.map(x=>rows([x]).replace('</div></div>',`</div></div>`)).join(""):empty(dq?"🔍":"🛰️",dq?"No match":"No devices yet",dq?"Try another name, IP or site.":"They appear after their first lookup.");
  $("gpdl").querySelectorAll(".gpdv").forEach(r=>{const x=l.find(y=>y.ip===r.dataset.ip);r.querySelector(".sub").insertAdjacentHTML("afterend","");0});
  bindRows($("gpdl"),l);open.forEach(ip=>$("gpdl").querySelector(`.gpdv[data-ip="${CSS.escape(ip)}"]`)?.click());
  $("gppstab").innerHTML=stabHTML(s);
  const all=[...Object.entries(n.manual||{}).map(([k,v])=>[k,v,"manual"]),...Object.entries(n.auto||{}).map(([k,v])=>[k,v,"from router"])].sort();
  $("gphs").textContent=`${all.length} names`;$("gphl").innerHTML=all.length?`<table class="gpt"><thead><tr><th>Name</th><th>Address</th><th>Source</th></tr></thead><tbody>${all.map(([k,v,src])=>`<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(v)}</td><td><span class="gpchip">${src}</span></td></tr>`).join("")}</tbody></table><div class="small" style="margin-top:8px">Add or edit names in Settings › Local names.</div>`:empty("🏷️","No .home names","Add one in Settings › Local names.")}catch(e){}}
$("gpdq")&&($("gpdq").oninput=e=>{dq=e.target.value.trim();clearTimeout(dTimer);dTimer=setTimeout(proDevices,250)});$("gpdo")&&($("gpdo").onchange=proDevices);
// ---------- customizable layout (edit mode, drag or arrows, hide/show, per browser) ----------
const LK="gplayout282";let lay={};try{lay=JSON.parse(localStorage[LK]||"{}")}catch(e){}
const cards=()=>[...document.querySelectorAll("#gps section.card,#gpp section.card,#dpane > section.card,#dpane > .v28g > section.card,#v28 section.card")].filter(c=>c.closest("#vpane")==null);
function keyOf(c){if(!c.dataset.k)c.dataset.k=c.id||("c-"+(c.querySelector(".lbl")?.textContent||"").trim().toLowerCase().replace(/[^a-z0-9]+/g,"-").slice(0,40));return c.dataset.k}
function applyLayout(){const cs=cards();cs.forEach(keyOf);cs.forEach(c=>c.classList.toggle("gphid",!!(lay.hidden||[]).includes(c.dataset.k)));
 const ord=lay.order||{};const groups=new Map();cs.forEach(c=>{const p=c.parentElement;if(!groups.has(p))groups.set(p,[]);groups.get(p).push(c)});
 groups.forEach((list,p)=>{const o=ord[list.map(c=>c.dataset.k).sort().join("|")];if(!o)return;const anchor=list[list.length-1].nextSibling;o.forEach(k=>{const c=list.find(x=>x.dataset.k===k);if(c)p.insertBefore(c,anchor)})})}
function saveLayout(){const cs=cards(),ord={},groups=new Map();cs.forEach(c=>{const p=c.parentElement;if(!groups.has(p))groups.set(p,[]);groups.get(p).push(c)});
 groups.forEach(list=>{ord[list.map(c=>c.dataset.k).sort().join("|")]=list.map(c=>c.dataset.k)});lay.order=ord;lay.hidden=cs.filter(c=>c.classList.contains("gphid")).map(c=>c.dataset.k);localStorage[LK]=JSON.stringify(lay)}
const bar=document.createElement("div");bar.id="gplay";bar.innerHTML=`<button class="btn" id="gplreset">Reset layout</button><button class="btn primary" id="gpldone">Done</button>`;document.body.appendChild(bar);
let dragEl=null;
function edit(on){document.body.classList.toggle("gpedit",on);cards().forEach(c=>{keyOf(c);c.draggable=on;let ctl=c.querySelector(":scope > .hd > .gpctl, :scope > .gpctl");
 if(on&&!ctl){ctl=document.createElement("span");ctl.className="gpctl";ctl.innerHTML=`<button title="Move up" aria-label="Move up">↑</button><button title="Move down" aria-label="Move down">↓</button><button title="Hide or show" aria-label="Hide or show">👁</button>`;(c.querySelector(":scope > .hd")||c).appendChild(ctl);
  const [u,d,h]=ctl.children;u.onclick=e=>{e.stopPropagation();const p=c.previousElementSibling;if(p&&p.matches("section.card"))c.parentElement.insertBefore(c,p);saveLayout()};
  d.onclick=e=>{e.stopPropagation();const n=c.nextElementSibling;if(n&&n.matches("section.card"))c.parentElement.insertBefore(n,c);saveLayout()};h.onclick=e=>{e.stopPropagation();c.classList.toggle("gphid");saveLayout()}}
 c.ondragstart=on?e=>{dragEl=c;c.classList.add("gpdrag");e.dataTransfer.effectAllowed="move"}:null;c.ondragend=on?()=>{c.classList.remove("gpdrag");dragEl=null;saveLayout()}:null;
 c.ondragover=on?e=>{if(!dragEl||dragEl===c||dragEl.parentElement!==c.parentElement)return;e.preventDefault();const r=c.getBoundingClientRect();c.parentElement.insertBefore(dragEl,(e.clientY-r.top)>r.height/2?c.nextSibling:c)}:null})}
$("gpldone").onclick=()=>edit(false);$("gplreset").onclick=()=>{localStorage.removeItem(LK);location.reload()};
const mb=$("gpmode");if(mb){const b=document.createElement("button");b.className="btn";b.id="gpcust";b.textContent="Customize";b.title="Rearrange, hide or show cards (saved in this browser)";b.style.marginLeft="8px";b.onclick=()=>edit(!document.body.classList.contains("gpedit"));mb.after(b)}
// ---------- phone bottom tab bar ----------
const tb=document.createElement("nav");tb.id="gptab";tb.setAttribute("aria-label","Sections");
tb.innerHTML=`<button data-t="home"><span>🏠</span>Home</button><button data-t="devices"><span>📱</span>Devices</button><button data-t="pro"><span>📊</span>Pro</button><button data-t="version"><span>✨</span>Version</button>`;document.body.appendChild(tb);
const setModeBtn=p=>$("gpmode")?.querySelector(`button[data-m="${p?"pro":"simple"}"]`)?.click();
tb.onclick=e=>{const b=e.target.closest("button");if(!b)return;const t=b.dataset.t;
 if(t==="version"){$("tabV")?.click()}else{if($("vpane")&&!$("vpane").classList.contains("hidden"))$("tabD")?.click();setModeBtn(t!=="home");if(t==="devices")setTimeout(()=>$("gpdev")?.scrollIntoView({behavior:RM.matches?"auto":"smooth",block:"start"}),60);else scrollTo({top:0,behavior:RM.matches?"auto":"smooth"})}
 syncTabs(t)};
function syncTabs(force){const v=$("vpane")&&!$("vpane").classList.contains("hidden");const t=force||(v?"version":document.body.classList.contains("gpp")?"pro":"home");tb.querySelectorAll("button").forEach(b=>b.classList.toggle("on",b.dataset.t===t))}
// ---------- smooth crossfade on tab / mode change (no reflow jump: keep min-height) ----------
const fade=el=>{if(!el||RM.matches)return;el.classList.remove("gpfade");void el.offsetWidth;el.classList.add("gpfade")};
{let pm=document.body.classList.contains("gpp");new MutationObserver(()=>{const p=document.body.classList.contains("gpp");if(p!==pm){pm=p;fade(p?$("gpp"):$("gps"))}syncTabs()}).observe(document.body,{attributes:true,attributeFilter:["class"]})}
["dpane","vpane"].forEach(id=>{const el=$(id);if(!el)return;let was=el.classList.contains("hidden");new MutationObserver(()=>{const h=el.classList.contains("hidden");if(h===was)return;was=h;if(!h)fade(el);syncTabs()}).observe(el,{attributes:true,attributeFilter:["class"]})});
// ---------- Ocam branding: footer + Version tab ----------
{const f=document.createElement("footer");f.id="gpfoot";f.style.cssText="text-align:center;font-size:12px;color:var(--muted);padding:22px 0 10px";f.innerHTML='GoProxy DNS · by <b style="font-weight:650;color:var(--text)">Ocam</b> · © 2026 Ocam';document.body.appendChild(f);
 const vp=$("vpane");if(vp){const a=document.createElement("div");a.className="card";a.style.cssText="margin:16px 0;text-align:center;padding:18px";a.innerHTML='<div class="lbl">About</div><div style="font-size:15px;margin-top:6px">GoProxy DNS <span id="gpabv"></span> · by <b>Ocam</b></div><div class="small">Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only </div>';vp.appendChild(a);api("/api/v282/stability").then(s=>$("gpabv").textContent="v"+s.version).catch(()=>{})}}
// ---------- boot ----------
setTimeout(applyLayout,1200);syncTabs();simpleTick();proDevices();setInterval(simpleTick,5000);setInterval(proDevices,6000);
document.body.addEventListener("click",e=>{if(e.target.closest('#gpmode button'))setTimeout(()=>{simpleTick();proDevices()},50)});
})();
