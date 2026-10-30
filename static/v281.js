// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
// GoProxy DNS v2.8.1: two-tier dashboard (Simple / Pro), Update impact card, version markers,
// Pro tools (query log, upstream histograms, cache inspector, raw metrics, config, ⌘K palette).
// Inspirations: Apple Activity ring + plain language (Simple); NextDNS / Control D analytics
// tiles and per-query log filters; AdGuard Home & Pi-hole query log (result chips, client
// filter, one-click allow/block style actions); Technitium cache browser (search + delete
// one record); Unbound stats / Prometheus text for raw metrics; Grafana annotations (version
// markers as dashed lines on time series); Cloudflare analytics (before/after deltas);
// Linear / Raycast (⌘K palette, single-key shortcuts); Vercel (dense, quiet Pro layout).
(()=>{"use strict";
const $=id=>document.getElementById(id),esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const RM=matchMedia("(prefers-reduced-motion: reduce)");let calm=RM.matches;RM.addEventListener?.("change",e=>calm=e.matches);
const H=window.HELP||(window.HELP={});
H.gpmode=["Simple or Pro","Simple shows how your DNS is doing in plain words. Pro adds every chart, the full query log, cache inspector, raw metrics, tuning and keyboard shortcuts (press ⌘K or Ctrl K).","Simple for everyday use."];
H.gpimpact=["Update impact","Each version is recorded with the time it was installed. The 24 hours before an update are compared with the 24 hours after it (or as much as has passed). Green = better, red = worse. Small changes (under 5%) are grey.","After a speed update: cold lookups faster, everything else about the same."];
H.gpqlog=["Query log","The last 5,000 lookups kept in memory (never written to disk). Filter by result, type or device, or search a name.","—"];
H.gpcache=["Cache inspector","Search what is cached, see the records and how long they stay, and remove one name so the next lookup asks the upstream again.","—"];
H.gphist=["Upstream latency","Distribution of each server's last answers (log scale), with its race wins and errors.","Most bars left of 50 ms."];
H.gpraw=["Raw metrics","Counters in Prometheus text format, the same numbers Grafana would scrape.","—"];
const api=async(u,o)=>{const r=await fetch(u,Object.assign({cache:"no-store"},o||{}));let j=null;const t=r.headers.get("content-type")||"";if(t.includes("json")){try{j=await r.json()}catch(e){}}else j=await r.text();if(!r.ok)throw new Error((j&&j.error)||r.statusText);return j};
const post=(u,b)=>api(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})});
const fmt=n=>Number(n||0).toLocaleString(),ms=v=>v==null||isNaN(v)?"–":v<1?v.toFixed(2)+" ms":v<10?v.toFixed(1)+" ms":Math.round(v)+" ms";
// resolve CSS colors (incl. light-dark()) to rgb via a probe element; alpha variants for gradients
const probe=document.createElement("i");probe.style.display="none";document.documentElement.appendChild(probe);
const col=(v,a)=>{probe.style.color="";probe.style.color=v;const m=getComputedStyle(probe).color.match(/[\d.]+/g)||[136,136,136];return a==null?`rgb(${m[0]},${m[1]},${m[2]})`:`rgba(${m[0]},${m[1]},${m[2]},${a})`};
const ago=t=>{const s=Date.now()/1e3-t;return s<90?"just now":s<5400?Math.round(s/60)+" min ago":s<129600?Math.round(s/3600)+" h ago":Math.round(s/86400)+" days ago"};
const css=document.createElement("style");css.textContent=`
body.gps #dpane>*:not(#gps){display:none!important}body:not(.gps) #gps{display:none}body:not(.gpp) .gpponly{display:none!important}
#gpmode button{min-width:58px}
.gps-hero{display:grid;grid-template-columns:230px 1fr;gap:22px;align-items:center}
@media(max-width:760px){.gps-hero{grid-template-columns:1fr;justify-items:center;text-align:center}}
.gps-ring{position:relative;width:200px;height:200px}.gps-ring svg{transform:rotate(-90deg)}.gps-ring .c{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gps-ring b{font-size:30px;font-weight:700;letter-spacing:-.03em}.gps-ring span{font-size:12.5px;color:var(--muted)}
.gps-kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}@media(max-width:560px){.gps-kpis{grid-template-columns:1fr}}
.gps-k{padding:14px 16px;border-radius:14px;background:var(--surface2)}.gps-k div:first-child{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:600}
.gps-k b{display:block;font-size:30px;font-weight:650;letter-spacing:-.03em;font-variant-numeric:tabular-nums;margin-top:2px}.gps-k em{font-style:normal;font-size:12px;color:var(--muted)}
.gps-line{font-size:15px;margin:2px 0 12px}.gps-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}@media(max-width:760px){.gps-row{grid-template-columns:1fr}}
.gps-dom{display:grid;grid-template-columns:20px 1fr auto;gap:4px 10px;align-items:center;padding:7px 0;border-top:1px solid color-mix(in srgb,var(--edge) 70%,transparent)}.gps-dom:first-child{border-top:0}
.gps-dom i{display:block;height:5px;border-radius:3px;background:linear-gradient(90deg,var(--accent),color-mix(in srgb,var(--accent) 50%,var(--green)));transition:width .9s var(--spring,ease)}
.gps-al{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-top:1px solid color-mix(in srgb,var(--edge) 70%,transparent)}.gps-al:first-child{border-top:0}
.gps-al .d{flex:none;width:9px;height:9px;border-radius:50%;margin-top:5px}
.gpimp table,.gpt{width:100%;border-collapse:collapse;font-size:13px;font-variant-numeric:tabular-nums}
.gpimp td,.gpimp th{padding:7px 8px;text-align:right;border-top:1px solid color-mix(in srgb,var(--edge) 70%,transparent)}.gpt td,.gpt th{padding:6px 8px;text-align:left;border-top:1px solid color-mix(in srgb,var(--edge) 70%,transparent)}
.gpimp td:first-child,.gpimp th:first-child,.gpt .n{text-align:right}.gpimp th,.gpt th{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:600;border-top:0}
.gpd{display:inline-block;min-width:58px;text-align:center;font-size:11.5px;font-weight:650;border-radius:999px;padding:2px 8px;animation:gpdin .5s var(--spring,ease) both}
.gpd.good{color:var(--green);background:color-mix(in srgb,var(--green) 14%,transparent)}.gpd.bad{color:var(--red);background:color-mix(in srgb,var(--red) 14%,transparent)}.gpd.same{color:var(--muted);background:var(--surface2)}
@keyframes gpdin{from{opacity:0;transform:scale(.7)}to{opacity:1;transform:none}}
.gpchips{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 12px}.gpchips button{border:1px solid var(--edge);background:transparent;color:var(--muted);font:inherit;font-size:12.5px;font-weight:600;padding:4px 11px;border-radius:999px;cursor:pointer;transition:all .25s}
.gpchips button.on{background:var(--accent);border-color:var(--accent);color:#fff}
.gptl{position:relative;height:30px;margin:6px 4px 14px}.gptl:before{content:"";position:absolute;left:0;right:0;top:14px;height:2px;border-radius:2px;background:var(--surface2)}
.gptl span{position:absolute;top:8px;width:14px;height:14px;margin-left:-7px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 3px var(--surface);cursor:pointer;transition:transform .3s var(--spring,ease)}.gptl span:hover,.gptl span.on{transform:scale(1.35)}
.gpbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.gpbar input,.gpbar select{font:inherit;font-size:13px;padding:6px 10px;border-radius:9px;border:1px solid var(--edge);background:var(--surface);color:var(--text)}
.gpbar input[type=search]{flex:1;min-width:170px}
.gpscroll{max-height:420px;overflow:auto;border-radius:10px}.gpt td.mono{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}.gpt tr{transition:background .2s}.gpt tbody tr:hover{background:color-mix(in srgb,var(--surface2) 60%,transparent)}
.gpt thead th{position:sticky;top:0;background:var(--surface);z-index:1}
.gpr{font-size:11px;font-weight:650;border-radius:999px;padding:1px 7px}.gpr.cached,.gpr.stale{color:var(--green);background:color-mix(in srgb,var(--green) 13%,transparent)}.gpr.forwarded,.gpr.refreshed{color:var(--accent);background:color-mix(in srgb,var(--accent) 13%,transparent)}.gpr.blocked,.gpr.threat{color:var(--red);background:color-mix(in srgb,var(--red) 13%,transparent)}.gpr.failed{color:var(--amber);background:color-mix(in srgb,var(--amber) 15%,transparent)}.gpr.local{color:var(--purple);background:color-mix(in srgb,var(--purple) 13%,transparent)}
.gph{display:grid;grid-template-columns:minmax(120px,190px) 1fr 150px;gap:12px;align-items:center;padding:8px 0;border-top:1px solid color-mix(in srgb,var(--edge) 70%,transparent)}.gph:first-child{border-top:0}
@media(max-width:760px){.gph{grid-template-columns:1fr}}
.gph .bars{display:flex;align-items:flex-end;gap:2px;height:38px}.gph .bars i{flex:1;border-radius:2px 2px 0 0;background:var(--accent);min-height:1px;transition:height .7s var(--spring,ease)}
.gpk{font:11px ui-monospace,monospace;padding:1px 6px;border-radius:5px;border:1px solid var(--edge);background:var(--surface2);color:var(--muted)}
body.gpp .card{padding:14px 16px}body.gpp .grid,body.gpp .v28g{gap:12px}body.gpp .v28g,body.gpp section.grid{margin-bottom:12px}body.gpp{font-size:13.5px}
#gpk{position:fixed;inset:0;z-index:80;display:none;align-items:flex-start;justify-content:center;padding-top:14vh;background:rgba(0,0,0,.28);-webkit-backdrop-filter:blur(3px);backdrop-filter:blur(3px)}
#gpk.on{display:flex;animation:gpfade .18s ease}@keyframes gpfade{from{opacity:0}to{opacity:1}}
#gpk>div{width:min(560px,92vw);border-radius:16px;overflow:hidden;border:1px solid var(--edge);background:color-mix(in srgb,var(--surface) 92%,transparent);-webkit-backdrop-filter:blur(24px) saturate(180%);backdrop-filter:blur(24px) saturate(180%);box-shadow:0 24px 70px rgba(0,0,0,.3);animation:gppop .28s var(--spring,ease)}
@keyframes gppop{from{opacity:0;transform:scale(.95) translateY(-6px)}to{opacity:1;transform:none}}
#gpk input{width:100%;box-sizing:border-box;border:0;border-bottom:1px solid var(--edge);background:transparent;color:var(--text);font:inherit;font-size:17px;padding:16px 18px;outline:none}
#gpkl{max-height:50vh;overflow:auto;padding:6px}#gpkl div{display:flex;justify-content:space-between;align-items:center;padding:9px 12px;border-radius:10px;cursor:pointer;font-size:14px}#gpkl div.on{background:color-mix(in srgb,var(--accent) 16%,transparent)}
@media (prefers-reduced-motion: reduce){.gpd,#gpk>div,#gpk.on{animation:none}.gps-dom i,.gph .bars i{transition:none}}`;
document.head.appendChild(css);
const dp=$("dpane"),hdr=document.querySelector("header .ctl");if(!dp)return;
// ---------- mode switch (replaces the old Expert switch; Pro also turns Expert details on) ----------
let pro=localStorage.gpmode?localStorage.gpmode==="pro":localStorage.expert==="1";
const oldSw=$("tog")&&$("tog").closest(".sw");if(oldSw)oldSw.style.display="none";
const seg=document.createElement("span");seg.className="sw";seg.innerHTML=`<span class="seg" id="gpmode" role="group" aria-label="Dashboard mode"><button data-m="simple">Simple</button><button data-m="pro">Pro</button></span><button class="q" data-h="gpmode">?</button>`;
hdr&&hdr.insertBefore(seg,hdr.firstChild.nextSibling);
function setMode(p,save){pro=p;if(save)localStorage.gpmode=p?"pro":"simple";document.body.classList.toggle("gpp",p);document.body.classList.toggle("gps",!p);
$("gpmode").querySelectorAll("button").forEach(b=>b.classList.toggle("on",(b.dataset.m==="pro")===p));
try{expert=p;localStorage.expert=p?"1":"0";setE()}catch(e){}
if(p){proLoad()}else simpleLoad();setTimeout(()=>{dispatchEvent(new Event("resize"));window.GP281redraw&&GP281redraw()},60)}
$("gpmode").onclick=e=>{const b=e.target.closest("button");if(b)setMode(b.dataset.m==="pro",true)};
// ---------- SIMPLE ----------
const S=document.createElement("div");S.id="gps";
S.innerHTML=`<section class="card" style="margin-bottom:16px"><div class="gps-hero"><div class="gps-ring" id="gpsring"><svg width="200" height="200" viewBox="0 0 200 200"><circle cx="100" cy="100" r="84" fill="none" stroke="var(--surface2)" stroke-width="16"/><circle id="gpsarc" cx="100" cy="100" r="84" fill="none" stroke="var(--green)" stroke-width="16" stroke-linecap="round" stroke-dasharray="0 528" style="transition:stroke-dasharray 1.2s var(--spring,ease),stroke .5s"/></svg><div class="c"><b id="gpsst">–</b><span id="gpsss">checking…</span></div></div>
<div><div class="gps-line" id="gpsline">Loading…</div><div class="gps-kpis"><div class="gps-k"><div>Average speed</div><b id="gpsk0">–</b><em id="gpse0"></em></div><div class="gps-k"><div>Answered from cache</div><b id="gpsk1">–</b><em id="gpse1"></em></div><div class="gps-k"><div>Ads &amp; trackers blocked</div><b id="gpsk2">–</b><em id="gpse2"></em></div></div></div></div></section>
<section class="card" style="margin-bottom:16px"><div class="hd"><div class="lbl">Live · last 2 minutes</div><div class="legend"><span><i style="background:var(--accent)"></i>Lookups/sec</span><span><i style="background:var(--green)"></i>Speed</span></div></div><canvas id="gpslive" style="width:100%;height:220px;display:block" role="img" aria-label="Live lookups and speed"></canvas></section>
<div class="gps-row"><section class="card"><div class="hd"><div class="lbl">Top sites</div><span class="small">since start</span></div><div id="gpstop"></div></section>
<section class="card"><div class="hd"><div class="lbl">What's happening</div></div><div id="gpsal"></div></section></div>
<div style="text-align:center;margin:18px 0 6px"><button class="btn" id="gpsmore">Show all details (Pro) →</button></div>`;
dp.prepend(S);$("gpsmore").onclick=()=>setMode(true,true);
const live=[];let lastQ=null,lastT=0,sTimer=0;
function drawLive(){const c=$("gpslive");if(!c||!c.offsetWidth)return;const dpr=devicePixelRatio||1,W=c.offsetWidth,Hh=c.offsetHeight;c.width=W*dpr;c.height=Hh*dpr;const g=c.getContext("2d");g.scale(dpr,dpr);g.clearRect(0,0,W,Hh);
const top=10,h=Hh-26;g.strokeStyle=col("var(--edge)");g.setLineDash([3,4]);for(let i=0;i<=3;i++){const y=top+h*i/3+.5;g.beginPath();g.moveTo(0,y);g.lineTo(W,y);g.stroke()}g.setLineDash([]);
if(live.length<2){g.fillStyle=col("var(--muted)");g.textAlign="center";g.fillText("Collecting…",W/2,top+h/2);return}
const n=60,x=i=>W-4-(live.length-1-i)*(W-8)/(n-1);
const line=(vals,mx,cc,fill)=>{const P=vals.map((v,i)=>[x(i),top+h-Math.min(v/mx,1)*h]);g.beginPath();P.forEach((p,i)=>{if(!i)g.moveTo(p[0],p[1]);else{const q=P[i-1],m=(q[0]+p[0])/2;g.bezierCurveTo(m,q[1],m,p[1],p[0],p[1])}});g.strokeStyle=cc;g.lineWidth=2.2;g.stroke();
if(fill){g.lineTo(P[P.length-1][0],top+h);g.lineTo(P[0][0],top+h);const gr=g.createLinearGradient(0,top,0,top+h);gr.addColorStop(0,cc.replace("rgb(","rgba(").replace(")",",.33)"));gr.addColorStop(1,cc.replace("rgb(","rgba(").replace(")",",0)"));g.fillStyle=gr;g.fill()}
const L=P[P.length-1];g.fillStyle=cc;g.beginPath();g.arc(L[0],L[1],3.4,0,7);g.fill()};
const q=live.map(p=>p.q),l=live.map(p=>p.l);line(q,Math.max(1,...q)*1.2,col("var(--accent)"),true);line(l,Math.max(5,...l)*1.3,col("var(--green)"),false);
g.fillStyle=col("var(--muted)");g.font="11px system-ui";g.fillText(Math.max(...q).toFixed(1)+"/s peak",6,Hh-6);g.textAlign="end";g.fillText("now",W-4,Hh-6)}
const ring=(v,c)=>{const a=$("gpsarc");a.style.stroke=col(c);requestAnimationFrame(()=>a.setAttribute("stroke-dasharray",`${Math.max(.02,Math.min(1,v))*528} 528`))};
let lastSt=null,lastV=null;
async function simpleTick(){if(pro||document.hidden)return;try{const [s,v]=await Promise.all([api("/api/stats"),lastV&&Date.now()-lastV.t<15000?lastV:api("/api/v28/status").then(x=>(x.t=Date.now(),x)).catch(()=>null)]);lastV=v;lastSt=s;
const now=Date.now();if(lastQ!=null&&now>lastT){live.push({q:Math.max(0,(s.queries-lastQ)/((now-lastT)/1e3)),l:s.p50_ms||0});if(live.length>60)live.shift()}lastQ=s.queries;lastT=now;
const issues=[],fails=s.queries?s.failures/s.queries:0,ups=s.upstreams||[],down=ups.filter(u=>u.health==="down");
if(down.length)issues.push(["amber",`${down.length===1?esc(down[0].label||down[0].name)+" is":down.length+" DNS servers are"} not answering — the others are covering for ${down.length===1?"it":"them"}.`]);
if(ups.length&&down.length===ups.length)issues.unshift(["red","No DNS server is answering. Websites may not load. Check the internet connection."]);
if(fails>.05&&s.queries>50)issues.push(["red",`${(fails*100).toFixed(0)}% of lookups are failing.`]);
if(s.p50_ms>80)issues.push(["amber",`Lookups are slower than usual (${ms(s.p50_ms)}).`]);
const ev=((v&&v.heal&&v.heal.events)||[]).slice(-3).reverse(),dt=((v&&v.detect&&v.detect.events)||[]).slice(-3).reverse();
const ok=!issues.length;$("gpsst").textContent=ok?"All good":issues.length+" issue"+(issues.length>1?"s":"");$("gpsss").textContent=ok?"DNS is healthy":"needs a look";
const health=ok?Math.min(1,.86+.14*(s.hit_ratio||0)):issues.some(i=>i[0]==="red")?.3:.62;ring(health,ok?"var(--green)":issues.some(i=>i[0]==="red")?"var(--red)":"var(--amber)");
$("gpsline").innerHTML=ok?`Everything is working. <span style="color:var(--muted)">${fmt(s.queries)} lookups since ${s.uptime_sec>86400?Math.round(s.uptime_sec/86400)+" days ago":"the last restart"}.</span>`:issues.map(i=>i[1]).join(" ");
$("gpsk0").textContent=ms(s.p50_ms);$("gpse0").textContent=s.hit_p50_ms?`cached ${ms(s.hit_p50_ms)}`:"";
$("gpsk1").textContent=s.queries?Math.round(100*(s.hit_ratio||0))+"%":"–";$("gpse1").textContent=s.queries?"faster when higher":"";
$("gpsk2").textContent=fmt(s.blocked);$("gpse2").textContent=s.blocking_available?(s.blocking_paused?"blocking paused":(100*(s.blocked_ratio||0)).toFixed(1)+"% of lookups"):"blocking off";
const top=(s.top_domains||[]).slice(0,5),mx=Math.max(1,...top.map(d=>d.requests||d.count||0));
$("gpstop").innerHTML=top.length?top.map((d,i)=>`<div class="gps-dom"><span class="small">${i+1}</span><div><div class="trunc">${esc(d.host||d.domain)}</div><i style="width:0" data-w="${100*(d.requests||d.count||0)/mx}%"></i></div><span class="small">${fmt(d.requests||d.count)}</span></div>`).join(""):`<div class="small">No lookups yet.</div>`;
requestAnimationFrame(()=>requestAnimationFrame(()=>$("gpstop").querySelectorAll("i[data-w]").forEach(i=>i.style.width=i.dataset.w)));
const al=[...issues.map(i=>[i[0],i[1],"now"]),...ev.map(e=>[e.kind==="recovered"?"green":"amber",esc(e.detail)+(e.action?` — ${esc(e.action)}.`:""),ago(e.t)]),...dt.map(e=>["red",`A device looked up a suspicious name (${esc(e.domain)}) — ${e.kind==="tunnel"?"possible data tunnel":"looks machine-generated"}.`,ago(e.t)])];
if(!al.length)al.push(["green","Nothing needs your attention.",""]);
$("gpsal").innerHTML=al.slice(0,6).map(a=>`<div class="gps-al"><span class="d" style="background:var(--${a[0]})"></span><div style="flex:1">${a[1]}</div><span class="small">${a[2]}</span></div>`).join("");drawLive()}catch(e){$("gpsline").textContent="Can't reach the server right now."}}
function simpleLoad(){clearInterval(sTimer);simpleTick();sTimer=setInterval(simpleTick,2000)}
addEventListener("resize",()=>{if(!pro)drawLive()});
// ---------- PRO ----------
const P=document.createElement("div");P.id="gpp";P.className="gpponly";
P.innerHTML=`<section class="card" id="gpql" style="margin-bottom:12px"><div class="hd"><div class="lbl">Query log <button class="q" data-h="gpqlog">?</button></div><span class="small" id="gpqls"></span></div>
<div class="gpbar"><input type="search" id="gpqq" placeholder="Search name or client   ( / )" aria-label="Search the query log"><select id="gpqr" aria-label="Result"><option value="">All results</option><option>cached</option><option>forwarded</option><option>stale</option><option>blocked</option><option>failed</option><option>local</option><option>threat</option></select>
<select id="gpqt" aria-label="Type"><option value="">All types</option><option>A</option><option>AAAA</option><option>HTTPS</option><option>CNAME</option><option>PTR</option><option>TXT</option><option>MX</option><option>SRV</option></select><select id="gpqc" aria-label="Device"><option value="">All devices</option></select>
<select id="gpqm" aria-label="Slower than"><option value="0">Any speed</option><option value="10">≥10 ms</option><option value="50">≥50 ms</option><option value="200">≥200 ms</option></select><button class="btn" id="gpqp">Pause</button></div>
<div class="gpscroll"><table class="gpt"><thead><tr><th>Time</th><th>Device</th><th>Name</th><th>Type</th><th>Result</th><th class="n">ms</th><th>Upstream</th></tr></thead><tbody id="gpqb"></tbody></table></div></section>
<div class="v28g"><section class="card" id="gpuh"><div class="hd"><div class="lbl">Upstream latency &amp; races <button class="q" data-h="gphist">?</button></div><span class="small" id="gpuhs"></span></div><div id="gpuhl"></div></section>
<section class="card" id="gpci"><div class="hd"><div class="lbl">Cache inspector <button class="q" data-h="gpcache">?</button></div><span class="small" id="gpcis"></span></div>
<div class="gpbar"><input type="search" id="gpcq" placeholder="Search cached names" aria-label="Search the cache"><button class="btn danger" id="gpcdn" title="Remove every record type of this name">Forget name</button></div>
<div class="gpscroll" style="max-height:330px"><table class="gpt"><thead><tr><th>Name</th><th>Type</th><th class="n">TTL</th><th class="n">Hits</th><th></th></tr></thead><tbody id="gpcb"></tbody></table></div></section></div>
<div class="v28g"><section class="card" id="gpraw"><div class="hd"><div class="lbl">Raw metrics <button class="q" data-h="gpraw">?</button></div><span><button class="btn" id="gprc">Copy</button> <a class="btn" href="/api/v28/pro/metrics" target="_blank" rel="noopener">Open</a></span></div><pre class="mono small" id="gprm" style="max-height:300px;overflow:auto;margin:0;white-space:pre"></pre></section>
<section class="card" id="gpcfg"><div class="hd"><div class="lbl">Configuration</div></div><div class="small" style="margin-bottom:12px">Export every setting as a JSON file (secrets stay sealed), or restore one. Per-feature tuning is in <a href="#" id="gpgos">Smart settings</a> below.</div>
<div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn" href="/api/settings/export" download="goproxy-settings.json">Export…</a><label class="btn">Import…<input type="file" id="gpimp" accept=".json,application/json" hidden></label></div><div class="small" id="gpimps" style="margin-top:8px"></div>
<div class="lbl" style="margin:18px 0 8px">Keyboard</div><div class="small" style="display:grid;grid-template-columns:auto 1fr;gap:6px 12px"><span><span class="gpk">⌘K</span> <span class="gpk">Ctrl K</span></span><span>Command palette</span><span class="gpk">/</span><span>Search the query log</span><span class="gpk">p</span><span>Simple ↔ Pro</span><span><span class="gpk">g</span> <span class="gpk">d</span> / <span class="gpk">g</span> <span class="gpk">v</span></span><span>Dashboard / Version tab</span><span class="gpk">r</span><span>Refresh</span><span class="gpk">Esc</span><span>Close</span></div></section></div>`;
const navEl=dp.querySelector(".v28nav");(navEl?navEl.after(P):dp.prepend(P));
if(navEl){for(const[t,id]of[["Queries","gpql"],["Cache","gpci"],["Raw","gpraw"]]){const b=document.createElement("button");b.dataset.s=id;b.textContent=t;b.className="gpponly";navEl.appendChild(b)}}
$("gpgos").onclick=e=>{e.preventDefault();$("v28st")?.scrollIntoView({behavior:calm?"auto":"smooth"})};
let paused=false,pTimer=0,clients=new Set();$("gpqp").onclick=()=>{paused=!paused;$("gpqp").textContent=paused?"Resume":"Pause"};
const qs=()=>new URLSearchParams({q:$("gpqq").value,result:$("gpqr").value,type:$("gpqt").value,client:$("gpqc").value,min_ms:$("gpqm").value,limit:400});
async function loadLog(){try{const d=await api("/api/v28/pro/log?"+qs());const b=$("gpqb");
b.innerHTML=d.entries.map(e=>{clients.add(e.client);return`<tr><td class="small">${esc(e.time)}</td><td class="mono">${esc(e.client)}</td><td class="trunc" style="max-width:320px" title="${esc(e.domain)}">${esc(e.domain)}</td><td>${esc(e.type)}</td><td><span class="gpr ${esc(e.result)}">${esc(e.result)}</span></td><td class="n">${e.latency_ms<1?e.latency_ms.toFixed(2):e.latency_ms.toFixed(0)}</td><td class="small trunc" style="max-width:150px">${esc(e.upstream||"")}</td></tr>`}).join("")||`<tr><td colspan="7" class="small">No matching lookups.</td></tr>`;
$("gpqls").textContent=`${fmt(d.entries.length)} shown · ${fmt(d.kept)} kept · `+Object.entries(d.counts).map(([k,v])=>`${k} ${fmt(v)}`).join(" · ");
const sel=$("gpqc"),cur=sel.value;if(sel.options.length-1!==clients.size){sel.innerHTML=`<option value="">All devices</option>`+[...clients].sort().map(c=>`<option ${c===cur?"selected":""}>${esc(c)}</option>`).join("")}}catch(e){$("gpqls").textContent=e.message}}
let qT=0;for(const id of["gpqq","gpqr","gpqt","gpqc","gpqm"])$(id).addEventListener("input",()=>{clearTimeout(qT);qT=setTimeout(loadLog,180)});
async function loadUps(){try{const d=await api("/api/v28/pro/upstreams");const B=d.bounds_ms;
$("gpuhs").textContent=`${d.smart?"smart race of "+d.smart_n:"race all"} · hedge fired ${fmt(d.hedged)}× · last winner ${d.last_winner||"–"}`;
$("gpuhl").innerHTML=d.upstreams.map(u=>{const mx=Math.max(1,...u.hist);return`<div class="gph"><div><div style="font-weight:600" class="trunc">${esc(u.label||u.name)}</div><div class="small">${esc(u.kind)} · <span style="color:var(--${u.health==="up"?"green":u.health==="down"?"red":"amber"})">${esc(u.health)}</span>${u.h3_ok?" · HTTP/3":""}</div></div>
<div><div class="bars" title="${u.hist.map((c,i)=>"≤"+B[i]+" ms: "+c).join("\n")}">${u.hist.map(c=>`<i style="height:${c?Math.max(4,100*c/mx):0}%;opacity:${c?1:.15}"></i>`).join("")}</div><div class="small" style="display:flex;justify-content:space-between"><span>0.05</span><span>1 ms</span><span>25</span><span>800</span></div></div>
<div class="small" style="text-align:right">p50 <b style="color:var(--text)">${ms(u.p50_ms)}</b> · p95 <b style="color:var(--text)">${ms(u.p95_ms)}</b><br>${fmt(u.wins)} wins of ${fmt(u.queries)} (${(100*u.win_rate).toFixed(0)}%)<br>${fmt(u.errors)} errors · ${fmt(u.cancelled)} lost races${u.warms?" · "+fmt(u.warms)+" warms":""}</div></div>`}).join("")}catch(e){}}
async function loadCache(){try{const d=await api("/api/v28/pro/cache?q="+encodeURIComponent($("gpcq").value));$("gpcis").textContent=`${fmt(d.matched)} match · ${fmt(d.entries_total)} cached`;
$("gpcb").innerHTML=d.entries.map(e=>`<tr title="${esc((e.answers||[]).join("\n"))}"><td class="trunc" style="max-width:240px">${esc(e.name)}${e.negative?' <span class="small">(no such name)</span>':""}<div class="small mono trunc" style="max-width:240px">${esc((e.answers||[])[0]||"")}</div></td><td>${esc(e.type)}</td><td class="n">${e.ttl_sec<0?`<span style="color:var(--amber)">stale ${-e.ttl_sec}s</span>`:e.ttl_sec+"s"}</td><td class="n">${fmt(e.hits)}</td><td><button class="btn" data-k="${esc(e.key)}" title="Remove this record">✕</button></td></tr>`).join("")||`<tr><td colspan="5" class="small">Nothing cached matches.</td></tr>`}catch(e){$("gpcis").textContent=e.message}}
let cT=0;$("gpcq").addEventListener("input",()=>{clearTimeout(cT);cT=setTimeout(loadCache,200)});
$("gpcb").addEventListener("click",async e=>{const b=e.target.closest("button[data-k]");if(!b)return;const tr=b.closest("tr");tr.style.transition="opacity .3s";tr.style.opacity=.3;await post("/api/v28/pro/cache",{key:b.dataset.k}).catch(()=>{});loadCache()});
$("gpcdn").onclick=async()=>{const n=$("gpcq").value.trim();if(!n)return $("gpcq").focus();const r=await post("/api/v28/pro/cache",{name:n}).catch(e=>({removed:0}));$("gpcis").textContent=`Removed ${r.removed} record${r.removed===1?"":"s"} of ${n}`;setTimeout(loadCache,400)};
async function loadRaw(){try{$("gprm").textContent=await api("/api/v28/pro/metrics")}catch(e){}}
$("gprc").onclick=()=>{navigator.clipboard?.writeText($("gprm").textContent);$("gprc").textContent="Copied ✓";setTimeout(()=>$("gprc").textContent="Copy",1500)};
$("gpimp").onchange=async e=>{const f=e.target.files[0];if(!f)return;const s=$("gpimps");try{const b=JSON.parse(await f.text());if(!confirm("Replace the current settings with "+f.name+"?"))return;await post("/api/settings/import",{backup:b});s.textContent="Imported ✓ — reloading…";s.style.color="var(--green)";setTimeout(()=>location.reload(),1200)}catch(err){s.textContent="Import failed: "+err.message;s.style.color="var(--red)"}e.target.value=""};
function proTick(){if(!pro||document.hidden||$("dpane").classList.contains("hidden"))return;if(!paused)loadLog();loadUps();loadRaw()}
function proLoad(){clearInterval(sTimer);clearInterval(pTimer);proTick();loadCache();pTimer=setInterval(proTick,4000)}
// ---------- Update impact (Version tab) ----------
const vp=$("vpane");let imp=null,impSel=-1,markers=[];
const IC=document.createElement("div");IC.className="card gpimp";IC.id="gpimp";IC.style.cssText="margin:18px 0;max-width:760px";
IC.innerHTML=`<div class="hd"><div class="lbl"><i style="width:8px;height:8px;border-radius:50%;background:var(--accent);display:inline-block"></i> Update impact <button class="q" data-h="gpimpact">?</button></div><span class="small" id="gpimps2"></span></div><div class="gptl" id="gptl"></div><div class="gpchips" id="gpich"></div><div id="gpib"><div class="small">Loading…</div></div>`;
vp&&($("cl")?vp.insertBefore(IC,$("cl")):vp.appendChild(IC));
const ROWS=[["Cold lookup, median","cold_median_ms",-1,ms],["Cold lookup, p95","cold_p95_ms",-1,ms],["Cold lookup, average","cold_avg_ms",-1,ms],["Cached, median","cached_median_ms",-1,ms],["Cached, p95","cached_p95_ms",-1,ms],["Cache hit","hit_pct",1,v=>v.toFixed(1)+"%"],["Failures","fail_pct",-1,v=>v.toFixed(2)+"%"],["CPU","cpu_pct",-1,v=>v.toFixed(2)+"%"],["Memory","mem_mb",-1,v=>v.toFixed(0)+" MB"]];
function delta(b,a,dir,key){if(b==null||a==null||(!b&&!a))return`<span class="gpd same">–</span>`;const pctMode=key.endsWith("_pct");const d=pctMode?a-b:(b?(a-b)/b*100:0);const rel=pctMode?(b?Math.abs(a-b)/Math.max(b,.5)*100:Math.abs(d)*20):Math.abs(d);
const cls=rel<5?"same":(d*dir>0?"good":"bad");const txt=pctMode?(d>0?"+":"")+d.toFixed(key==="fail_pct"?2:1)+" pt":(d>0?"+":"")+d.toFixed(0)+"%";return`<span class="gpd ${cls}">${cls==="same"&&Math.abs(d)<.05?"same":txt}</span>`}
function impRender(){if(!imp)return;const C=imp.compare||[];if(!C.length){$("gpib").innerHTML=`<div class="small">No versions recorded yet.</div>`;return}
if(impSel<0||impSel>=C.length)impSel=C.length-1;const c=C[impSel],B=c.before,A=c.after;
const t0=Math.min(...C.map(x=>x.t))-86400,t1=Date.now()/1e3;$("gptl").innerHTML=C.map((x,i)=>`<span data-i="${i}" class="${i===impSel?"on":""}" style="left:${(x.t-t0)/(t1-t0)*100}%" title="v${esc(x.version)} · ${new Date(x.t*1e3).toLocaleString()}"></span>`).join("");
$("gpich").innerHTML=C.map((x,i)=>`<button data-i="${i}" class="${i===impSel?"on":""}">v${esc(x.version)}</button>`).join("");
$("gpimps2").textContent=`installed ${new Date(c.t*1e3).toLocaleString([], {month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}${c.estimated?" (estimated)":""}`;
const has=w=>w&&w.lookups>0,det=w=>w&&w.detail;
const val=(w,k)=>!w?null:k.startsWith("cold_")&&k!=="cold_avg_ms"&&!w.cold_n?null:k.startsWith("cached_")&&!w.cached_n?null:k==="cold_avg_ms"&&!w.cold_avg_ms?null:(k.startsWith("cold_med")||k.startsWith("cold_p95")||k.startsWith("cached_")||k==="cpu_pct"||k==="mem_mb")?(det(w)?w[k]:null):has(w)?w[k]:null;
$("gpib").innerHTML=`<table><thead><tr><th>${c.prev?`v${esc(c.prev)} → v${esc(c.version)}`:`v${esc(c.version)}`}</th><th>24 h before</th><th>${c.complete?"24 h after":`after (${c.after_hours<1?Math.round(c.after_hours*60)+" min":c.after_hours.toFixed(1)+" h"} so far)`}</th><th>Change</th></tr></thead><tbody>`+
ROWS.map(([t,k,dir,f])=>{const b=val(B,k),a=val(A,k);return`<tr><td>${t}</td><td>${b==null?'<span class="small">not measured</span>':f(b)}</td><td>${a==null?'<span class="small">collecting…</span>':f(a)}</td><td>${b==null||a==null?'<span class="gpd same">–</span>':delta(b,a,dir,k)}</td></tr>`}).join("")+
`</tbody></table><div class="small" style="margin-top:10px">${fmt(B.lookups)} lookups before · ${fmt(A.lookups)} after. Percentiles, CPU and memory are recorded from v2.8.1 on; older versions show the averages kept in the history file.</div>`}
IC.addEventListener("click",e=>{const b=e.target.closest("[data-i]");if(b){impSel=+b.dataset.i;impRender()}});
async function loadImpact(){try{imp=await api("/api/v28/impact");markers=imp.markers||[];impRender();window.GP281redraw&&GP281redraw()}catch(e){try{markers=(await api("/api/version?brief=1")).markers||[]}catch(_){}}}
loadImpact();setInterval(()=>{if(!document.hidden)loadImpact()},60000);
// version markers on the speed history chart (Grafana-style annotations)
window.GP281={markers(g,x,top,h,t0,t1,prog){if(!markers.length)return;g.save();g.font="600 10.5px system-ui";for(const m of markers){if(m.t<t0||m.t>t1)continue;const X=Math.round(x(m.t))+.5;if(X>g.canvas.width/(devicePixelRatio||1)*prog)continue;
const cc=col("var(--amber)");g.strokeStyle=cc;g.globalAlpha=.85;g.setLineDash([4,4]);g.lineWidth=1.2;g.beginPath();g.moveTo(X,top+14);g.lineTo(X,top+h);g.stroke();g.setLineDash([]);
const lb="v"+m.version,w=g.measureText(lb).width+10;let lx=Math.min(Math.max(X-w/2,2),g.canvas.width/(devicePixelRatio||1)-w-2);g.globalAlpha=1;g.fillStyle=cc;g.beginPath();g.roundRect?g.roundRect(lx,top,w,15,7):g.rect(lx,top,w,15);g.fill();g.fillStyle="#fff";g.fillText(lb,lx+5,top+11)}g.restore()}};
// ---------- ⌘K palette + shortcuts ----------
const K=document.createElement("div");K.id="gpk";K.innerHTML=`<div role="dialog" aria-label="Command palette"><input id="gpki" placeholder="Type a command…" autocomplete="off" spellcheck="false"><div id="gpkl"></div></div>`;document.body.appendChild(K);
const tab=v=>$(v?"tabV":"tabD")?.click();
const go=id=>{if(!pro)setMode(true,true);tab(false);setTimeout(()=>$(id)?.scrollIntoView({behavior:calm?"auto":"smooth",block:"start"}),80)};
const CMDS=[["Switch to Simple",()=>setMode(false,true),"p"],["Switch to Pro",()=>setMode(true,true),"p"],["Dashboard tab",()=>tab(false),"g d"],["Version tab",()=>tab(true),"g v"],["Update impact",()=>{tab(true);setTimeout(()=>$("gpimp").scrollIntoView({behavior:"smooth"}),80)}],
["Query log",()=>go("gpql"),"/"],["Cache inspector",()=>go("gpci")],["Upstream latency",()=>go("gpuh")],["Raw metrics",()=>go("gpraw")],["Smart settings",()=>go("v28st")],["Speed history",()=>go("v28sp")],
["Flush the whole cache",()=>$("flush")?.click()],["Pause / resume ad blocking",()=>$("btog")?.click()],["Export settings",()=>{location.href="/api/settings/export"}],["Import settings…",()=>{go("gpcfg");setTimeout(()=>$("gpimp").click(),300)}],["Check for updates",()=>{tab(true);$("upchk")?.click()}],["Log out",()=>$("logout")?.click()]];
let kSel=0,kList=CMDS;const kRender=()=>{$("gpkl").innerHTML=kList.map((c,i)=>`<div data-i="${i}" class="${i===kSel?"on":""}"><span>${esc(c[0])}</span>${c[2]?`<span class="gpk">${esc(c[2])}</span>`:""}</div>`).join("")||`<div class="small">No match</div>`;$("gpkl").querySelector(".on")?.scrollIntoView({block:"nearest"})};
const kOpen=()=>{K.classList.add("on");$("gpki").value="";kList=CMDS;kSel=0;kRender();setTimeout(()=>$("gpki").focus(),10)},kClose=()=>K.classList.remove("on"),kRun=i=>{const c=kList[i];kClose();c&&c[1]()};
$("gpki").addEventListener("input",e=>{const q=e.target.value.toLowerCase().split(/\s+/).filter(Boolean);kList=CMDS.filter(c=>q.every(w=>c[0].toLowerCase().includes(w)));kSel=0;kRender()});
$("gpki").addEventListener("keydown",e=>{if(e.key==="ArrowDown"){kSel=Math.min(kList.length-1,kSel+1);kRender();e.preventDefault()}else if(e.key==="ArrowUp"){kSel=Math.max(0,kSel-1);kRender();e.preventDefault()}else if(e.key==="Enter"){kRun(kSel)}else if(e.key==="Escape")kClose()});
$("gpkl").addEventListener("click",e=>{const d=e.target.closest("[data-i]");if(d)kRun(+d.dataset.i)});K.addEventListener("click",e=>{if(e.target===K)kClose()});
let gPend=0;addEventListener("keydown",e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k"){e.preventDefault();K.classList.contains("on")?kClose():kOpen();return}
if(e.key==="Escape"){kClose();return}const t=e.target;if(t.closest&&t.closest("input,textarea,select,[contenteditable]")||e.metaKey||e.ctrlKey||e.altKey)return;
if(gPend&&Date.now()-gPend<900){gPend=0;if(e.key==="d")tab(false);else if(e.key==="v")tab(true);return}
if(e.key==="g"){gPend=Date.now();return}if(e.key==="p"){setMode(!pro,true)}else if(e.key==="/"){e.preventDefault();go("gpql");setTimeout(()=>$("gpqq").focus(),120)}else if(e.key==="r"){pro?proTick():simpleTick();loadImpact()}});
document.addEventListener("visibilitychange",()=>{if(!document.hidden)(pro?proTick:simpleTick)()});
setMode(pro,false);
})();
