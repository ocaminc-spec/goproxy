// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
// GoProxy DNS v2.7.0: live insights (top domains, blocked/failed feed, 24 h heat grid,
// upstream race), per-device live view, and the Protection, alerts, sync & backup settings.
// Same look as the Live graph: monotone curves, soft gradients, thin grid, big numbers.
(()=>{"use strict";
const $=id=>document.getElementById(id),esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const H=window.HELP||{};
H.v27top=["Top domains","The names asked for most in the last 1 or 5 minutes, counted only while this page is open.","A few familiar services at the top; nothing unknown hammering."];
H.v27feed=["Blocked & failed","Lookups that were blocked (filter or device rule) or failed, newest first. Device addresses appear only with Devices by volume on.","Mostly ads/trackers when blocking is on; failures rare."];
H.v27heat=["Response-time heat grid","24 hours in 10-minute columns. Each row is a response-time band; brighter = more answers in that band.","Bright band at the bottom (fast), little above 100 ms."];
H.v27race=["Upstream race","Each lookup that misses the cache is sent to the upstreams; the first answer wins. Win share and average time per upstream, per second.","Both upstreams winning some; times under ~30 ms."];
H.v27set=["Protection, alerts, sync & backup","Ad & tracker blocking (off until you switch it on), alert thresholds with an optional webhook (ntfy, Pushover or JSON), settings sync between peers (newest change wins), peer watch and nightly backups (7 kept).","Webhook tested once; sync shows peers in sync; a backup from last night."];
H.v27dev=["Devices live","Per-device query rate and rules (block, bedtime). Shown and enforced only with Devices by volume switched on.","No device far above its usual rate."];
const api=async(u,o)=>{const r=await fetch(u,Object.assign({cache:"no-store"},o||{}));let j=null;try{j=await r.json()}catch(e){}if(!r.ok)throw new Error((j&&j.error)||r.statusText);return j};
const post=(u,b)=>api(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})});
const AC={top:"var(--accent)",feed:"var(--red)",heat:"var(--amber)",race:["var(--accent)","var(--purple)","var(--green)","#14b8a6"],dev:"#14b8a6",set:"var(--purple)"};
const st=document.createElement("style");st.textContent=`
.v27g{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;margin-bottom:16px}
.v27c{border-radius:18px;transition:box-shadow .25s,transform .25s}.v27c:hover{box-shadow:0 6px 24px rgba(0,0,0,.08)}
.v27big{font-size:28px;font-weight:650;line-height:1.15;font-variant-numeric:tabular-nums}
.v27k{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted)}
.v27bar{position:relative;height:26px;border-radius:9px;overflow:hidden;margin:4px 0;display:flex;align-items:center;padding:0 10px;font-size:13px}
.v27bar i{position:absolute;inset:0 auto 0 0;border-radius:9px;opacity:.9;transition:width .6s cubic-bezier(.2,.8,.2,1)}
.v27bar span{position:relative;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.v27bar b{position:relative;font-weight:600;font-variant-numeric:tabular-nums}
.v27feed{max-height:260px;overflow:auto}.v27fi{display:flex;gap:8px;padding:6px 4px;border-bottom:1px solid color-mix(in srgb,var(--edge) 50%,transparent);font-size:13px;animation:v27in .45s ease}
@keyframes v27in{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.v27pill{font-size:11px;border-radius:999px;padding:1px 8px;white-space:nowrap}
.v27seg button{border-radius:9px;min-width:auto;font-size:12px;padding:3px 10px}
.v27f{display:grid;grid-template-columns:1fr auto;gap:8px 12px;align-items:center;margin:6px 0}
.v27f input[type=text],.v27f input[type=password],.v27f input[type=number],.v27f select,.v27ta{font:inherit;padding:7px 10px;border-radius:10px;background:transparent;color:inherit;border:1px solid var(--edge);transition:border-color .2s}
.v27ta{width:100%;box-sizing:border-box;min-height:64px}.v27f input:focus,.v27ta:focus{outline:none;border-color:var(--purple)}
.v27sec{border-top:1px solid color-mix(in srgb,var(--edge) 60%,transparent);padding-top:12px;margin-top:12px}
.v27sec h4{margin:0 0 6px;font-size:13px;font-weight:650;display:flex;align-items:center;gap:6px}.v27sec h4 i{width:8px;height:8px;border-radius:50%;display:inline-block}
`;document.head.appendChild(st);
const host=$("v26srv")||$("health");if(!host)return;
const wrap=document.createElement("div");wrap.id="v27";
const hd=(id,t,h,acc,extra)=>`<div class="hd"><div class="lbl"><i style="width:8px;height:8px;border-radius:50%;background:${acc};display:inline-block;margin-right:6px"></i>${t} <button class="q" data-h="${h}">?</button></div>${extra||""}</div>`;
wrap.innerHTML=`<div class="v27g">
<section class="card v27c" id="v27top">${hd("","Top domains","v27top",AC.top,`<span class="seg v27seg" id="v27win"><button class="btn" data-w="1" aria-pressed="true">1 min</button><button class="btn" data-w="5">5 min</button></span>`)}
<div style="display:flex;gap:24px;margin:2px 0 10px"><div><div class="v27big" id="v27tt" style="color:${AC.top}">–</div><div class="v27k">lookups in window</div></div><div><div class="v27big" id="v27tn">–</div><div class="v27k">distinct names</div></div></div><div id="v27tl" class="small">Collecting…</div></section>
<section class="card v27c" id="v27fd">${hd("","Blocked &amp; failed","v27feed",AC.feed,`<span class="small" id="v27fs"></span>`)}
<div style="display:flex;gap:24px;margin:2px 0 10px"><div><div class="v27big" id="v27bt" style="color:var(--amber)">–</div><div class="v27k">blocked since start</div></div><div><div class="v27big" id="v27ft" style="color:${AC.feed}">–</div><div class="v27k">failed since start</div></div></div><div class="v27feed" id="v27fl"><div class="small">Nothing blocked or failed yet.</div></div></section>
<section class="card v27c" id="v27rc">${hd("","Upstream race","v27race",AC.race[0])}<div id="v27rl" style="display:flex;flex-wrap:wrap;gap:12px 28px;margin:2px 0 8px"></div><canvas id="v27rcv" style="width:100%;height:200px;display:block" role="img" aria-label="Upstream race, last 2 minutes"></canvas><div class="small">Win share per second (solid) and average answer time (dashed), last 2 minutes.</div></section>
<section class="card v27c" id="v27ht">${hd("","Response-time heat grid · 24 h","v27heat",AC.heat,`<span class="small" id="v27hs"></span>`)}<canvas id="v27hcv" style="width:100%;height:220px;display:block" role="img" aria-label="Response time heat grid, last 24 hours"></canvas><div class="small" id="v27htip" style="min-height:1.3em">Hover a column for details.</div></section>
</div>
<section class="card v27c" id="v27dv" style="margin-bottom:16px">${hd("","Devices live","v27dev",AC.dev,`<span class="small" id="v27dvs"></span>`)}<div id="v27dvl" class="small">Loading…</div></section>
<section class="card v27c" id="v27st" style="margin-bottom:16px">${hd("","Protection, alerts, sync &amp; backup","v27set",AC.set,`<span class="small" id="v27msg"></span>`)}<div id="v27form" class="small">Loading…</div></section>`;
host.after(wrap);
const pr=document.createElement("i");pr.style.display="none";wrap.appendChild(pr);
const col=v=>{pr.style.color=v;const c=getComputedStyle(pr).color;pr.style.color="";return c},rgba=(c,a)=>c.replace(/^rgba?\(([^,]+),([^,]+),([^,)]+).*$/,`rgba($1,$2,$3,${a})`);
function curve(g,P){const n=P.length;if(!n)return;g.moveTo(P[0][0],P[0][1]);if(n<3){for(const p of P)g.lineTo(p[0],p[1]);return}
const d=[],m=[];for(let i=0;i<n-1;i++){const dx=P[i+1][0]-P[i][0];d.push(dx?(P[i+1][1]-P[i][1])/dx:0)}
m[0]=d[0];m[n-1]=d[n-2];for(let i=1;i<n-1;i++)m[i]=d[i-1]*d[i]<=0?0:(d[i-1]+d[i])/2;
for(let i=0;i<n-1;i++){if(!d[i]){m[i]=m[i+1]=0;continue}const a=m[i]/d[i],b=m[i+1]/d[i],h=a*a+b*b;if(h>9){const t=3/Math.sqrt(h);m[i]=t*a*d[i];m[i+1]=t*b*d[i]}}
for(let i=0;i<n-1;i++){const dx=(P[i+1][0]-P[i][0])/3;g.bezierCurveTo(P[i][0]+dx,P[i][1]+m[i]*dx,P[i+1][0]-dx,P[i+1][1]-m[i+1]*dx,P[i+1][0],P[i+1][1])}}
function ctx(c){const dpr=devicePixelRatio||1,W=c.clientWidth,H=c.clientHeight;if(!W)return null;if(c.width!==Math.round(W*dpr)||c.height!==Math.round(H*dpr)){c.width=Math.round(W*dpr);c.height=Math.round(H*dpr)}const g=c.getContext("2d");g.setTransform(dpr,0,0,dpr,0,0);g.clearRect(0,0,W,H);g.font="11px system-ui,sans-serif";g.lineJoin="round";g.lineCap="round";return{g,W,H}}
const fmt=n=>Number(n||0).toLocaleString(),ago=t=>{const s=Math.max(0,Math.round(Date.now()/1e3-t/1e3));return s<60?s+" s":Math.round(s/60)+" min"};
// ---- insights ----
let win=+(localStorage.getItem("v27win")||1),since=0,race=[],rOff=0,ease={},rMx=0,raf=0,lastT=0,feedN=0,feedTot=0;
function setWin(w){win=w;localStorage.setItem("v27win",w);for(const b of $("v27win").querySelectorAll("button")){const on=+b.dataset.w===w;b.setAttribute("aria-pressed",on);b.style.fontWeight=on?"650":""}}
$("v27win").querySelectorAll("button").forEach(b=>b.onclick=()=>{setWin(+b.dataset.w);loadIns()});setWin(win);
function tops(j){const t=j.top||[],mx=t.length?t[0].count:1,a=col(AC.top);$("v27tt").textContent=fmt(j.top_total);$("v27tn").textContent=fmt(t.length)+(t.length>=15?"+":"");
$("v27tl").innerHTML=t.length?t.map((r,i)=>`<div class="v27bar" title="${esc(r.name)}"><i style="width:${Math.max(4,100*r.count/mx)}%;background:linear-gradient(90deg,${rgba(a,.30)},${rgba(a,.08)})"></i><span>${esc(r.name)}</span><b>${fmt(r.count)}</b></div>`).join(""):'<div class="small">No lookups yet in this window (counting starts when this page is open).</div>'}
function feed(j){$("v27bt").textContent=fmt(j.blocked_total);$("v27ft").textContent=fmt(j.failed_total);$("v27fs").textContent=j.blocking_on?"blocking on":"blocking off";
const f=j.feed||[];if(!f.length)return;since=Math.max(since,...f.map(x=>x.t));const box=$("v27fl");if(!feedN)box.innerHTML="";
const html=f.slice().sort((a,b)=>b.t-a.t).map(x=>`<div class="v27fi" data-t="${x.t}"><span class="v27pill" style="background:${x.result==="blocked"?"color-mix(in srgb,var(--amber) 18%,transparent);color:var(--amber)":"color-mix(in srgb,var(--red) 18%,transparent);color:var(--red)"}">${x.result}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.name)}">${esc(x.name)} <span class="small">${esc(x.type)}</span></span>${x.client?`<span class="small">${esc(x.client)}</span>`:""}<span class="small" data-ago="${x.t}">${ago(x.t)}</span></div>`).join("");
box.insertAdjacentHTML("afterbegin",html);feedN+=f.length;while(box.children.length>80)box.lastElementChild.remove()}
async function loadIns(){if(document.hidden)return;try{const j=await api("/api/v27/insights?window="+win+"&since="+since);tops(j);feed(j);race=j.race||[];const L=race[race.length-1];if(L){const o=L.t+1-Date.now()/1e3;rOff=Math.abs(o-rOff)>2?o:rOff+(o-rOff)*.2}start()}catch(e){$("v27tl").textContent=e.message}
for(const s of document.querySelectorAll("#v27fl [data-ago]"))s.textContent=ago(+s.dataset.ago)}
function ups(){const s=new Set();for(const p of race)for(const k in p.ups)s.add(k);return[...s].sort()}
function drawRace(dt){const c=$("v27rcv"),o=ctx(c);if(!o)return;const{g,W,H}=o,U=ups(),now=Date.now()/1e3+rOff-1,x=t=>W-(now-t)/120*W,P=race.filter(p=>p.t>=now-122);
const top=8,h=H-24;const grid=col("var(--faint)");g.strokeStyle=grid;g.lineWidth=1;g.globalAlpha=.18;g.setLineDash([2,4]);g.beginPath();for(const fr of[0,.5])g.moveTo(0,Math.round(top+fr*h)+.5),g.lineTo(W,Math.round(top+fr*h)+.5);g.stroke();g.setLineDash([]);g.globalAlpha=.3;g.beginPath();g.moveTo(0,top+h+.5);g.lineTo(W,top+h+.5);g.stroke();g.globalAlpha=1;
let tm=Math.max(5,...P.flatMap(p=>Object.values(p.ups).map(u=>u.avg_ms||0)))*1.15;rMx=rMx?rMx+(tm-rMx)*.12:tm;
U.forEach((u,i)=>{const cc=col(AC.race[i%AC.race.length]);const seg=k=>{const S=[];let s=[];for(const p of P){const v=p.ups[u];if(!v||(k==="avg_ms"&&!v.wins&&!v.avg_ms)){if(s.length)S.push(s);s=[];continue}s.push([x(p.t),top+h-Math.min((k==="share"?v.share:v.avg_ms/rMx),1)*h])}if(s.length)S.push(s);return S};
const S=seg("share");const gr=g.createLinearGradient(0,top,0,top+h);gr.addColorStop(0,rgba(cc,.22));gr.addColorStop(1,rgba(cc,0));g.fillStyle=gr;for(const s of S){if(s.length<2)continue;g.beginPath();curve(g,s);g.lineTo(s[s.length-1][0],top+h);g.lineTo(s[0][0],top+h);g.closePath();g.fill()}
g.strokeStyle=cc;g.lineWidth=2;g.beginPath();for(const s of S)curve(g,s);g.stroke();g.setLineDash([3,3]);g.globalAlpha=.55;g.lineWidth=1.3;g.beginPath();for(const s of seg("avg_ms"))curve(g,s);g.stroke();g.setLineDash([]);g.globalAlpha=1});
g.fillStyle=col("var(--muted)");g.globalAlpha=.6;g.fillText("2 min",6,H-2);g.fillText("now",W-24,H-2);const mt=Math.round(rMx/1.15)+" ms";g.fillText("100% · "+mt,W-g.measureText("100% · "+mt).width-6,top+10);g.globalAlpha=1;
// legend: eased big numbers over the last 10 s
const a=1-Math.exp(-dt/250),R=race.slice(-10);let html="";U.forEach((u,i)=>{let w=0,t=0,l=0,n=0;for(const p of R){const v=p.ups[u];if(v){w+=v.wins;if(v.avg_ms){l+=v.avg_ms;n++}}for(const k in p.ups)t+=p.ups[k].wins}
const sh=t?100*w/t:0,ms=n?l/n:0;for(const[k,v]of[["s"+u,sh],["m"+u,ms]])ease[k]=ease[k]==null?v:ease[k]+(v-ease[k])*a;const cl=AC.race[i%AC.race.length];
html+=`<div style="min-width:130px"><div class="small" style="display:flex;align-items:center;gap:6px"><i style="width:8px;height:8px;border-radius:50%;background:${cl};display:inline-block"></i>${esc(u)}</div><div class="v27big" style="color:${cl}">${ease["s"+u].toFixed(0)}%</div><div class="small">wins · ${ease["m"+u]?ease["m"+u].toFixed(ease["m"+u]<10?1:0)+" ms avg":"–"}</div></div>`});
$("v27rl").innerHTML=html||'<div class="small">Waiting for cache misses…</div>'}
let rLeg=0;function frame(t){raf=0;if(document.hidden)return;raf=requestAnimationFrame(frame);if(t-lastT<30)return;const dt=lastT?t-lastT:33;lastT=t;if(t-rLeg>90||!rLeg){rLeg=t;drawRace(dt*3)}else drawRace(0)}
function start(){if(!raf&&!document.hidden){lastT=0;raf=requestAnimationFrame(frame)}}
// ---- heat grid ----
const BANDS=["≤0.1","≤0.5","≤1","≤5","≤10","≤25","≤50","≤100","≤250","≤1000",">1000"];let heat=[],hAlpha=0,hHover=-1;
function drawHeat(){const c=$("v27hcv"),o=ctx(c);if(!o)return;const{g,W,H}=o,L=34,B=heat.length||144,cw=(W-L)/B,rh=(H-18)/11,a=col(AC.heat),grn=col("var(--green)"),red=col("var(--red)");
let mx=1;for(const b of heat)for(const v of(b.hist||[]))mx=Math.max(mx,v);
g.fillStyle=col("var(--muted)");g.globalAlpha=.7;for(let r=0;r<11;r+=2)g.fillText(BANDS[r],0,H-18-r*rh-rh/2+4);g.globalAlpha=1;
heat.forEach((b,i)=>{const hs=b.hist||[];for(let r=0;r<11;r++){const v=hs[r]||0;if(!v)continue;const k=Math.pow(v/mx,.45)*hAlpha;const base=r<=4?grn:r<=7?a:red;g.fillStyle=rgba(base,(.08+.85*k).toFixed(3));
const x=L+i*cw,y=H-18-(r+1)*rh;g.beginPath();g.roundRect?g.roundRect(x+.5,y+.5,Math.max(1,cw-1),rh-1,Math.min(3,cw/3)):g.rect(x+.5,y+.5,Math.max(1,cw-1),rh-1);g.fill()}});
if(hHover>=0&&hHover<B){g.strokeStyle=col("var(--text)");g.globalAlpha=.35;g.strokeRect(L+hHover*cw+.5,.5,cw-1,H-19);g.globalAlpha=1}
g.fillStyle=col("var(--muted)");g.globalAlpha=.6;g.fillText("24 h ago",L,H-3);g.fillText("now",W-24,H-3);g.fillText("ms",0,10);g.globalAlpha=1}
function heatAnim(){hAlpha=0;const t0=performance.now();const st=t=>{hAlpha=Math.min(1,(t-t0)/600);drawHeat();if(hAlpha<1)requestAnimationFrame(st)};requestAnimationFrame(st)}
$("v27hcv").addEventListener("mousemove",e=>{const r=e.target.getBoundingClientRect(),B=heat.length||144,i=Math.floor((e.clientX-r.left-34)/((r.width-34)/B));hHover=i;drawHeat();const b=heat[i];
if(!b){$("v27htip").textContent="Hover a column for details.";return}const hs=b.hist||[],n=hs.reduce((s,v)=>s+v,0);let acc=0,p95="–";for(let k=0;k<11;k++){acc+=hs[k]||0;if(n&&acc>=n*.95){p95=BANDS[k]+" ms";break}}
$("v27htip").textContent=`${new Date(b.start*1e3).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})} · ${fmt(n)} answers · p95 ${p95}`});
$("v27hcv").addEventListener("mouseleave",()=>{hHover=-1;drawHeat()});
async function loadHeat(){if(document.hidden)return;try{const j=await api("/api/health");const first=!heat.length;heat=j.buckets||[];const n=heat.reduce((s,b)=>s+(b.hist||[]).reduce((a,v)=>a+v,0),0);$("v27hs").textContent=fmt(n)+" answers";first?heatAnim():drawHeat()}catch(e){}}
// ---- devices live ----
let devOn=false;
async function loadDev(){if(document.hidden)return;try{const j=await api("/api/v27/devices/live");devOn=j.enabled;if(!j.enabled){$("v27dv").style.display="none";return}$("v27dv").style.display="";
const d=(j.devices||[]).slice().sort((a,b)=>b.per_min-a.per_min).slice(0,20),mx=Math.max(1,...d.map(x=>x.per_min)),a=col(AC.dev);$("v27dvs").textContent=d.length+" devices";
$("v27dvl").innerHTML=d.length?d.map(x=>`<div class="v27bar"${x.spike?' title="Spike: far above its hourly average"':""}><i style="width:${Math.max(3,100*x.per_min/mx)}%;background:linear-gradient(90deg,${rgba(x.spike?col("var(--red)"):a,.32)},${rgba(a,.06)})"></i><span>${x.spike?"⚠ ":""}${esc(x.name||x.ip)} ${x.name?`<span class="small">${esc(x.ip)}</span>`:""}</span><b>${fmt(x.per_min)}<span class="small">/min</span></b></div>`).join(""):'<div class="small">No device traffic yet.</div>'}catch(e){$("v27dvl").textContent=e.message}}
// ---- settings ----
let cfg=null,meta=null;
const sw=(id,on)=>`<label style="display:inline-flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="${id}" ${on?"checked":""} style="accent-color:var(--purple);width:18px;height:18px"></label>`;
const sec=(t,c,body)=>`<div class="v27sec"><h4><i style="background:${c}"></i>${t}</h4>${body}</div>`;
const lines=a=>(a||[]).join("\n"),unl=v=>v.split(/[\n,]/).map(s=>s.trim()).filter(Boolean);
function rulesHTML(r){return(r||[]).map(x=>`${x.ip}${x.name?" "+x.name:""}${x.block?" block":""}${(x.bedtime||[]).map(b=>" bedtime "+b.from+"-"+b.to+(b.days?"@"+b.days:"")).join("")}`).join("\n")}
function parseRules(t){return unl(t.replace(/,/g,"\n")).map(l=>{const f=l.split(/\s+/),r={ip:f.shift(),bedtime:[]};const nm=[];while(f.length){const w=f.shift();if(w==="block")r.block=true;else if(w==="bedtime"&&f.length){const[tm,days]=f.shift().split("@");const[from,to]=tm.split("-");r.bedtime.push({target:r.ip,mode:"on",from,to,days:days||""})}else nm.push(w)}r.name=nm.join(" ");return r})}
async function loadCfg(){try{const j=await api("/api/v27/config");cfg=j.config||{};meta=j;render()}catch(e){$("v27form").textContent=e.message}}
function render(){const c=cfg,m=meta,up=m.block_updated?new Date(m.block_updated*1e3).toLocaleString():"never";
$("v27form").innerHTML=
sec("Ad &amp; tracker blocking",AC.feed,`<div class="v27f"><span>Block ads and trackers <span class="small">(off until you switch it on)</span></span>${sw("v27bon",c.block_on)}</div>
<div style="display:flex;gap:24px;margin:4px 0 8px"><div><div class="v27big" style="color:var(--amber)">${fmt(m.blocked)}</div><div class="v27k">blocked lookups</div></div><div><div class="v27big">${fmt(m.block_size)}</div><div class="v27k">names on lists</div></div><div><div class="small" style="margin-top:8px">${m.block_updating?"updating…":"updated "+esc(up)}</div></div></div>
<div class="small">Subscriptions (one URL per line; empty = StevenBlack + OISD)</div><textarea class="v27ta" id="v27bl" placeholder="${esc(lines(m.default_lists))}">${esc(lines(c.block_lists))}</textarea>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px"><div><div class="small">Always allow</div><textarea class="v27ta" id="v27ba">${esc(lines(c.block_allow))}</textarea></div><div><div class="small">Always block</div><textarea class="v27ta" id="v27bd">${esc(lines(c.block_deny))}</textarea></div></div>`)+
sec("Alerts",AC.heat,`<div class="v27f"><span>Alert when DNS is slow or failing</span>${sw("v27aon",!c.alerts_off)}</div><div class="v27f"><span>Slow: 95% of answers above (ms, 5 min)</span><input type="number" id="v27slow" min="20" max="5000" value="${c.alert_slow_ms||300}" style="width:90px"></div><div class="v27f"><span>Failing: more than (% of lookups, 5 min)</span><input type="number" id="v27fail" min="1" max="100" value="${c.alert_fail_pct||20}" style="width:90px"></div>
<div class="v27f"><span>Send alerts to a webhook <span class="small">(off; at most one per alert every 30 min)</span></span>${sw("v27won",c.webhook_on)}</div>
<div class="v27f"><span>Kind</span><select id="v27wk">${["ntfy","pushover","json"].map(k=>`<option ${c.webhook_kind===k||(!c.webhook_kind&&k==="ntfy")?"selected":""}>${k}</option>`).join("")}</select></div>
<div class="v27f"><span>URL <span class="small">(stored encrypted)</span></span><input type="password" id="v27wu" autocomplete="off" value="${esc(c.webhook_url)}" placeholder="https://ntfy.sh/your-topic" style="width:220px"></div>
<div class="v27f"><span>Token <span class="small">(ntfy bearer / Pushover app token)</span></span><input type="password" id="v27wt" autocomplete="off" value="${esc(c.webhook_token)}" style="width:220px"></div>
<div class="v27f"><span>Pushover user key</span><input type="text" id="v27wus" value="${esc(c.webhook_user)}" style="width:220px"></div>
<button class="btn" id="v27wtest">Send test</button>`)+
sec("Peers: sync &amp; watch",AC.set,`<div class="v27f"><span>Sync settings and blocklists with peers automatically <span class="small">(newest change wins)</span></span>${sw("v27son",!c.sync_off)}</div><div class="v27f"><span>Alert when a peer stops answering</span>${sw("v27pw",!c.watch_off)}</div>
<button class="btn" id="v27sync">Sync now</button> <span class="small" id="v27ss"></span><div id="v27slog" class="small" style="margin-top:6px"></div>`)+
sec("Nightly backup",AC.race[2],`<div class="v27f"><span>Back up settings and sign-in data every night <span class="small">(7 kept in the data folder)</span></span>${sw("v27bk",!c.backup_off)}</div><button class="btn" id="v27bnow">Back up now</button> <span class="small" id="v27bs"></span><div id="v27blist" class="small" style="margin-top:6px"></div>`)+
(m.device_feature?sec("Device rules",AC.dev,`<div class="small">One device per line: <code>IP [name] [block] [bedtime 22:00-07:00[@mon,tue]]</code></div><textarea class="v27ta" id="v27dr">${esc(rulesHTML(c.device_rules))}</textarea>`):sec("Device rules",AC.dev,'<div class="small">Per-device blocking and bedtime need Devices by volume (Advanced &gt; Feature switches).</div>'))+
`<div style="margin-top:14px"><button class="btn pri" id="v27save">Save</button></div>`;
$("v27save").onclick=save;$("v27wtest").onclick=async()=>{try{await post("/api/v27/webhook/test");msg("Test sent.")}catch(e){msg(e.message,1)}};
$("v27sync").onclick=async()=>{$("v27ss").textContent="Syncing…";try{const j=await post("/api/v27/sync");$("v27ss").textContent=(j.notes||[]).join(" · ");loadSync();loadCfg()}catch(e){$("v27ss").textContent=e.message}};
$("v27bnow").onclick=async()=>{try{const j=await post("/api/v27/backup");$("v27bs").textContent=`Saved ${j.name} (${j.files} files).`;loadBk()}catch(e){$("v27bs").textContent=e.message}};loadSync();loadBk()}
function msg(t,bad){const e=$("v27msg");e.textContent=t;e.style.color=bad?"var(--red)":"";e.style.transition="opacity .4s";e.style.opacity=1;clearTimeout(msg.t);msg.t=setTimeout(()=>e.style.opacity=0,4000)}
async function save(){const n=Object.assign({},cfg,{block_on:$("v27bon").checked,block_lists:unl($("v27bl").value),block_allow:unl($("v27ba").value),block_deny:unl($("v27bd").value),alerts_off:!$("v27aon").checked,alert_slow_ms:+$("v27slow").value,alert_fail_pct:+$("v27fail").value,
webhook_on:$("v27won").checked,webhook_kind:$("v27wk").value,webhook_url:$("v27wu").value,webhook_token:$("v27wt").value,webhook_user:$("v27wus").value,sync_off:!$("v27son").checked,watch_off:!$("v27pw").checked,backup_off:!$("v27bk").checked});
if($("v27dr"))n.device_rules=parseRules($("v27dr").value);try{const j=await post("/api/v27/config",n);cfg=j.config;msg("Saved.");loadCfg()}catch(e){msg(e.message,1)}}
async function loadSync(){try{const j=await api("/api/v27/sync");$("v27slog").innerHTML=(j.peers?`Last change ${j.stamp?new Date(j.stamp).toLocaleString():"–"}${j.from?" from "+esc(j.from):""}.`:"No peers set up (Servers &amp; Health &gt; Set up peers).")+(j.log||[]).slice(-5).reverse().map(l=>`<div>${esc(new Date(l.at).toLocaleTimeString())} · ${esc(l.peer)}: ${esc(l.what)}</div>`).join("")}catch(e){}}
async function loadBk(){try{const j=await api("/api/v27/backup");$("v27blist").innerHTML=(j.backups||[]).length?(j.backups||[]).map(b=>`<div>${esc(b.name)} · ${b.files.length} files · ${(b.bytes/1024).toFixed(0)} KB</div>`).join(""):"No backups yet."}catch(e){}}
document.addEventListener("visibilitychange",()=>{if(!document.hidden){loadIns();start()}});addEventListener("resize",()=>drawHeat());
loadIns();loadHeat();loadDev();loadCfg();setInterval(loadIns,2000);setInterval(loadHeat,60000);setInterval(loadDev,5000);
})();
