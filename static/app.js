// app.js — dashboard client for app.py (extracted from the PAGE template).
// Served at /static/app.js. Talks to the /api/* + /evidence/* endpoints via SSE.
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let BOOT=null, ES=null, COUNTS={}, RESN=0;
let ROWS=[], RUNID=null, SORT={col:"n",dir:1}, RUNNING=false, EVRUNS=[];
let RUNCFG={}, CURTGT=null, PROG={};   // live run config / current target / module progress
// 6-bucket visual grouping (spectrum / legend / row colors)
const KIND={SUCCESS:"got",DETECTED:"det",BLOCKED:"blk","NO-SERVICE":"svc",
 "AUTH-FAILED":"det","NO-RESULT":"det",INCONCLUSIVE:"inc",SKIPPED:"skip","PREREQ-MISSING":"skip"};
// one harmonised palette, shared by every colored element on the page
const HEX={got:"#ff5f6e",det:"#f7a93b",blk:"#38d9a0",svc:"#5aa2ff",inc:"#b79bff",skip:"#6f8296"};
const LABEL={got:"got through",det:"detected / review",blk:"held",svc:"no service",inc:"inconclusive",skip:"skipped"};
const ORDER=["got","det","blk","svc","inc","skip"];
// exact verdict -> hex (verdict key + history rollup), kept consistent with the buckets above
const VHEX={SUCCESS:HEX.got,DETECTED:HEX.det,"AUTH-FAILED":HEX.det,"NO-RESULT":HEX.det,
 BLOCKED:HEX.blk,"NO-SERVICE":HEX.svc,INCONCLUSIVE:HEX.inc,SKIPPED:HEX.skip,"PREREQ-MISSING":HEX.skip};
const esc=s=>(s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const kindOf=v=>KIND[v]||"det";
const vcolor=v=>VHEX[v]||HEX[kindOf(v)];

async function boot(){
 BOOT=await (await fetch("api/bootstrap")).json();
 const s=$("#subline"); s.innerHTML="";
 const bits=["<b>v"+esc(BOOT.version)+"</b>"+(BOOT.engine?(" ("+esc(BOOT.engine)+")"):""), esc(BOOT.policy||"no policy"), BOOT.modules.length+" modules"];
 bits.forEach(t=>{const x=document.createElement("span");x.innerHTML=t;s.appendChild(x);});
 $("#workers").value=BOOT.workers; $("#roe").checked=BOOT.roe; syncRoe();
 const cl=BOOT.creds_loaded, L=$("#loaded"); L.innerHTML="";
 Object.entries(cl).forEach(([k,v])=>{const e=document.createElement("span");
  e.innerHTML=esc(k.replace("_"," "))+" <b class="+(v?"ok":"no")+">"+(v?"set":"—")+"</b>";L.appendChild(e);});
 const C=BOOT.creds||{};
 $("#domain").value=C.domain||""; $("#dcuser").value=C.dc_user||""; $("#dcpass").value=C.dc_pass||"";
 $("#sshuser").value=C.ssh_user||""; $("#sshpass").value=C.ssh_pass||"";
 syncSshCreds();                       // SSH login follows the Windows/DC Administrator by default
 $("#dcuser").addEventListener("input",onDcLoginChange);
 $("#dcpass").addEventListener("input",onDcLoginChange);
 $("#sshuser").addEventListener("input",onSshLoginChange);
 $("#sshpass").addEventListener("input",onSshLoginChange);
 if(Object.values(cl).some(Boolean) || Object.keys(BOOT.target_config||{}).length)
   { const d=$("#credpanel"); if(d) d.open=true; }
 // one editable row per known target (posture + net from its saved profile); the
 // FIRST row also drives the shared creds panel. No targets yet -> one blank row.
 const tgts=BOOT.targets||[];
 if(tgts.length){ tgts.forEach(ip=>{const tc=(BOOT.target_config||{})[ip]||{};
    addTargetRow(ip, String(tc.mode||"").toLowerCase().startsWith("w")?"whitebox":"blackbox", isCloudTarget(ip)||!!tc.cloud);});
    prefillTarget(tgts[0]); }
 else { addTargetRow("","blackbox",false); }
 $("#addtgt").addEventListener("click",()=>{addTargetRow("","blackbox",false).querySelector(".tip").focus();});
 buildBattery(); buildVerdictKey(); applyPreset("original"); refresh(); renderRows(); loadRuns();
}

// ---- per-target rows: IP + posture (black/white) + net (on-prem/cloud) ----
function segVal(seg){const on=seg.querySelector("button.on");return on?on.dataset.v:seg.querySelector("button").dataset.v;}
function setSeg(seg,val){[...seg.children].forEach(b=>b.classList.toggle("on",b.dataset.v===val));}
function mkSeg(kind,val,opts){
 const seg=document.createElement("div"); seg.className="rseg "+kind;
 opts.forEach(([v,label,title])=>{const b=document.createElement("button");b.type="button";b.dataset.v=v;b.textContent=label;if(title)b.title=title;if(v===val)b.classList.add("on");seg.appendChild(b);});
 seg.addEventListener("click",e=>{const b=e.target.closest("button");if(!b)return;setSeg(seg,b.dataset.v);});
 return seg;
}
function targetRows(){return $$("#targetRows .trow");}
function firstTargetRow(){return $("#targetRows .trow");}
function addTargetRow(ip,posture,cloud){
 const host=$("#targetRows");
 const row=document.createElement("div"); row.className="trow";
 const inp=document.createElement("input"); inp.className="tip"; inp.type="text"; inp.placeholder="host / IP"; inp.value=ip||"";
 const pseg=mkSeg("posture",posture||"blackbox",[["blackbox","black","through the SD-WAN as-is"],["whitebox","white","allow-all baseline"]]);
 const nseg=mkSeg("net",cloud?"cloud":"onprem",[["onprem","on-prem","SMB/RPC direct 445/135"],["cloud","cloud","NAT'd 4445/1135"]]);
 const rm=document.createElement("button"); rm.type="button"; rm.className="trm"; rm.title="remove target"; rm.textContent="✕";
 rm.addEventListener("click",()=>{ if(targetRows().length>1){row.remove();} else {inp.value="";} });
 const onIp=()=>onTargetIp(row,inp.value.trim());
 inp.addEventListener("change",onIp); inp.addEventListener("blur",onIp);
 row.append(inp,pseg,nseg,rm); host.appendChild(row);
 return row;
}
// Typing a known IP recalls that target's saved posture + net; the first row also
// fills the shared creds panel (like the desktop GUI's primary row).
// Canonical cloud DCs (159/167) are ALWAYS cloud — the server forces 4445/1135
// regardless, and the UI reflects it so the net toggle can't mislabel the run.
function isCloudTarget(ip){ return (BOOT.cloud_targets||[]).includes(String(ip||"").trim()); }
function onTargetIp(row,ip){
 if(isCloudTarget(ip)) setSeg(row.querySelector(".rseg.net"), "cloud");
 const tc=(BOOT.target_config||{})[ip]; if(!tc) return;
 setSeg(row.querySelector(".rseg.posture"), String(tc.mode||"").toLowerCase().startsWith("w")?"whitebox":"blackbox");
 if(!isCloudTarget(ip)) setSeg(row.querySelector(".rseg.net"), tc.cloud?"cloud":"onprem");
 if(firstTargetRow()===row) prefillTarget(ip);
}
function readTargetRows(){
 return targetRows().map(row=>({
   target: row.querySelector(".tip").value.trim(),
   posture: segVal(row.querySelector(".rseg.posture")),
   cloud: segVal(row.querySelector(".rseg.net"))==="cloud"
 })).filter(r=>r.target);
}
// Prefill the shared creds panel + NAT-port defaults for ONE target from its config.
function prefillTarget(ip){
 const tc=(BOOT.target_config||{})[ip]; if(!tc) return;
 if(tc.smb_port) $("#smb").value=tc.smb_port;
 if(tc.rpc_port) $("#rpc").value=tc.rpc_port;
 if(tc.ssh_port) $("#sshp").value=tc.ssh_port;
 if(tc.source) $("#source").value=tc.source;
 if(tc.site_id) $("#site").value=tc.site_id;
 if(tc.domain) $("#domain").value=tc.domain;
 if(tc.dc_user) $("#dcuser").value=tc.dc_user;
 if(tc.dc_pass) $("#dcpass").value=tc.dc_pass;
 if(tc.ssh_user) $("#sshuser").value=tc.ssh_user;
 if(tc.ssh_pass) $("#sshpass").value=tc.ssh_pass;
 syncSshCreds();   // SSH follows the Windows/DC login unless this target has a distinct one
}
// ---- SSH login MIRRORS the Windows/DC Administrator (same identity) ----
let SSH_TRACKS_DC=true;
function onDcLoginChange(){ if(SSH_TRACKS_DC){ $("#sshuser").value=$("#dcuser").value; $("#sshpass").value=$("#dcpass").value; } }
function onSshLoginChange(){ const su=$("#sshuser").value,sp=$("#sshpass").value,du=$("#dcuser").value,dp=$("#dcpass").value;
 // Windows usernames are case-insensitive (administrator == Administrator); passwords are not.
 SSH_TRACKS_DC=((!su.trim()||su.toLowerCase()===du.toLowerCase())&&(!sp.trim()||sp===dp)); }
function syncSshCreds(){ if(!$("#sshuser").value.trim()&&$("#dcuser").value.trim())$("#sshuser").value=$("#dcuser").value;
 if(!$("#sshpass").value.trim()&&$("#dcpass").value.trim())$("#sshpass").value=$("#dcpass").value; onSshLoginChange(); }
function syncRoe(){ $("#roeswitch").classList.toggle("armed",$("#roe").checked); }

// Verdict key: every verdict with color + plain-language meaning; each chip also toggles the table filter.
function buildVerdictKey(){
 const host=$("#vkey"); if(!host)return; host.innerHTML="";
 (BOOT.verdict_order||[]).forEach(v=>{
  const c=vcolor(v), g=(BOOT.verdict_gloss||{})[v]||"";
  const el=document.createElement("div"); el.className="vk"; el.dataset.v=v; el.title=v+" — "+g;
  el.innerHTML=`<i class=sw style="color:${c}"></i><b>${esc(v)}</b>`;
  el.addEventListener("click",()=>{
    const f=$("#fverdict");
    if(f.value===v){f.value="";}
    else{ if(![...f.options].some(o=>o.value===v)){const o=document.createElement("option");o.value=o.textContent=v;f.appendChild(o);} f.value=v; }
    renderRows();});
  host.appendChild(el);});
}
function markVerdictKey(){const cur=$("#fverdict").value;
 $$("#vkey .vk").forEach(el=>el.classList.toggle("on",el.dataset.v===cur&&cur!==""));}
function buildBattery(){
 const host=$("#battery"); host.innerHTML="";
 const byCat={}; BOOT.modules.forEach(m=>{(byCat[m.category]=byCat[m.category]||[]).push(m);});
 Object.keys(byCat).sort().forEach(cat=>{
  host.insertAdjacentHTML("beforeend",`<div class=cat><span class=cn>${esc(cat)}</span><span class=cl></span></div>`);
  byCat[cat].forEach(m=>{
   const flags=(m.added?'<span class="flag new">new</span>':'')+(m.needs_root?'<span class="flag root">root</span>':'');
   const mi=(m.mitre||[]).join(", "), cw=(m.cwe||[]).join(", ");
   const det=[m.category, m.tactic, (m.family?("family "+m.family):""), m.direction,
     (mi?("ATT&CK "+mi):""), (cw?("CWE "+cw):""), (m.cve?("CVE "+m.cve):""),
     (m.ports?("ports "+m.ports):""), (m.control?("control: "+m.control):""),
     (m.fix?("owner: "+m.fix):""), (m.test_type?("["+m.test_type+"]"):"")
     ].filter(Boolean).join("  •  ");
   host.insertAdjacentHTML("beforeend",
    `<label class=atk title="${esc(det)}"><input type=checkbox data-id="${m.id}">`
    +`<span class=nm>${esc(m.name)}</span>${flags}`
    +`<span class=mi>${esc(mi||'—')}${cw?(' <i class=cwe>'+esc(cw)+'</i>'):''}</span></label>`);
  });
 });
 host.addEventListener("change",updSel);
}
function applyPreset(p){const ids=p==="none"?[]:(BOOT.presets[p]||[]);
 $$("#battery input").forEach(cb=>cb.checked=ids.includes(cb.dataset.id));updSel();}
function updSel(){$("#selcount").textContent=$$("#battery input:checked").length+" armed";}
const selectedIds=()=>$$("#battery input:checked").map(cb=>cb.dataset.id);

function refresh(){
 const groups={}; let total=0;
 Object.entries(COUNTS).forEach(([v,n])=>{const k=kindOf(v);groups[k]=(groups[k]||0)+n;total+=n;});
 const spec=$("#spectrum");
 if(!total){spec.innerHTML='<div class=empty>no results yet</div>';}
 else{spec.innerHTML=ORDER.filter(k=>groups[k]).map(k=>
   `<i style="width:${100*groups[k]/total}%;background:${HEX[k]}" title="${LABEL[k]}: ${groups[k]}"></i>`).join("");}
 $("#legend").innerHTML=ORDER.map(k=>{const n=groups[k]||0;
  return `<span class="li${n?'':' z'}"><i class=sw style="color:${HEX[k]}"></i><b class=n>${n}</b><span class=nm>${LABEL[k]}</span></span>`;}).join("");
 const got=groups.got||0;
 const ft=$("#findtally"); ft.textContent=got; ft.classList.toggle("zero",got===0);
 $("#disttotal").textContent=total?(total+" check"+(total===1?"":"s")):"";
 $("#anchortotal").textContent=total?("of "+total+" check"+(total===1?"":"s")):(RUNNING?"running…":"no results yet");
}

function addRow(e){
 const row={n:++RESN, verdict:e.verdict||"", id:e.id||"", name:e.name||"", category:e.category||"",
  target:e.target||"", posture:e.posture||"", ports:e.ports||"", mitre:e.mitre||"", cwe:e.cwe||"", it:e.it||1, detail:e.detail||"", time:e.ts||""};
 ROWS.push(row);
 COUNTS[e.verdict]=(COUNTS[e.verdict]||0)+1;
 syncFilterOptions(); renderRows(row.n); refresh();
}
function syncFilterOptions(){
 const add=(sel,vals)=>{const cur=sel.value; const have=new Set([...sel.options].map(o=>o.value));
  [...vals].sort().forEach(v=>{if(v&&!have.has(v)){const o=document.createElement("option");o.value=o.textContent=v;sel.appendChild(o);}});
  sel.value=cur;};
 add($("#fverdict"), new Set(ROWS.map(r=>r.verdict)));
 add($("#fcat"),     new Set(ROWS.map(r=>r.category)));
 add($("#ftarget"),  new Set(ROWS.map(r=>r.target)));
}
function filteredRows(){
 const q=$("#fq").value.trim().toLowerCase(), fv=$("#fverdict").value, fc=$("#fcat").value, ft=$("#ftarget").value;
 let rows=ROWS.filter(r=>(!fv||r.verdict===fv)&&(!fc||r.category===fc)&&(!ft||r.target===ft)
   &&(!q||[r.name,r.detail,r.mitre,r.cwe,r.id,r.category,r.target,r.posture].join(" ").toLowerCase().includes(q)));
 const c=SORT.col, d=SORT.dir, num=(c==="n"||c==="it");
 rows.sort((a,b)=>{let x=a[c],y=b[c]; if(num){x=+x;y=+y;} else {x=(""+x).toLowerCase();y=(""+y).toLowerCase();}
   return x<y?-d:x>y?d:a.n-b.n;});
 return rows;
}
// toggle results chrome (table vs empty-state); insN = row number just inserted (for the entrance anim)
function updateResultsChrome(){
 const empty=ROWS.length===0;
 $("#resToolbar").classList.toggle("hidden",empty);
 $("#resWrap").classList.toggle("hidden",empty);
 $("#paneRes .vkeywrap").classList.toggle("hidden",empty);
 $("#resempty").classList.toggle("hidden",!empty);
 if(empty){
  const run=RUNNING;
  $("#resempty").classList.toggle("run",run);
  $("#resemptyT").textContent=run?"Running — awaiting first result":"No results yet";
  $("#resemptyS").textContent=run?"Live verdicts stream in as each module finishes.":"Pick a target, arm the battery, and run.";
 }
}
function renderRows(insN){
 updateResultsChrome();
 const rows=filteredRows(), tb=$("#resbody"); tb.innerHTML="";
 rows.forEach(r=>{const c=HEX[kindOf(r.verdict)];
  const tr=document.createElement("tr");
  tr.dataset.id=r.id; tr.dataset.it=r.it; tr.dataset.target=r.target;
  if(insN&&r.n===insN) tr.className="ins";
  tr.innerHTML=`<td class="mono cell-n">${r.n}</td>`
   +`<td><span class=vchip style="color:${c}"><span class=d></span><span class=t>${esc(r.verdict)}</span></span></td>`
   +`<td class=modcell>${esc(r.name)}</td><td class=dim>${esc(r.category)}</td>`
   +`<td class=mono>${esc(r.target)}</td>`
   +`<td>${r.posture?`<span class="pchip ${r.posture[0]==='w'?'w':'b'}">${r.posture[0]==='w'?'white':'black'}</span>`:'<span class=dim>—</span>'}</td>`
   +`<td class=mono>${esc(r.ports)}</td>`
   +`<td class=mono>${esc(r.mitre)}</td><td class=mono>${esc(r.cwe)}</td><td class="mono cell-n">${r.it}</td>`
   +`<td class=detail title="${esc(r.detail)}">${esc(r.detail)}</td>`
   +`<td class="mono dim">${esc(r.time)}</td>`;
  tr.addEventListener("click",()=>openRow(r));
  tb.appendChild(tr);});
 markVerdictKey();
 $("#rowcount").textContent=ROWS.length?(rows.length+(rows.length===ROWS.length?"":" / "+ROWS.length)+" rows"):"";
 $$("#restable thead th").forEach(th=>{const a=th.querySelector(".ar"); if(a)a.remove();
  if(th.dataset.col===SORT.col){const s=document.createElement("span");s.className="ar";s.textContent=SORT.dir>0?"▲":"▼";th.appendChild(s);}});
}
// click a results row -> fetch that module's raw output and show it in the drawer
async function openRow(r){
 const c=HEX[kindOf(r.verdict)];
 $("#dtitle").innerHTML=`<span class=vchip style="color:${c}"><span class=d></span><span class=t>${esc(r.verdict)}</span></span><span class=nm>${esc(r.name)}</span>`;
 $("#dmeta").innerHTML=[r.target,r.posture,r.category,r.ports,r.mitre&&("ATT&CK "+r.mitre),r.cwe&&("CWE "+r.cwe),"iter "+r.it]
   .filter(Boolean).map(x=>"<span>"+esc(x)+"</span>").join("");
 $("#dbody").textContent="loading raw output…";
 openDrawer();
 if(!RUNID){$("#dbody").textContent=r.detail||"(no run context)";return;}
 try{
  const u="api/run/"+RUNID+"/output?target="+encodeURIComponent(r.target)+"&id="+encodeURIComponent(r.id)+"&it="+encodeURIComponent(r.it);
  const j=await (await fetch(u)).json();
  $("#dbody").textContent=j.output!=null?j.output:("(no captured output — "+(j.error||"")+")\n\nverdict detail:\n"+r.detail);
 }catch(err){$("#dbody").textContent="(could not load output: "+err+")\n\nverdict detail:\n"+r.detail;}
}
function openDrawer(){$("#scrim").hidden=false;$("#drawer").hidden=false;}
function closeDrawer(){$("#scrim").hidden=true;$("#drawer").hidden=true;}
// export the CURRENTLY FILTERED rows
function exportRows(fmt){
 const rows=filteredRows(), cols=["n","verdict","name","id","category","target","posture","ports","mitre","cwe","it","detail"];
 let data,mime,ext;
 if(fmt==="json"){data=JSON.stringify(rows,null,1);mime="application/json";ext="json";}
 else if(fmt==="md"){data="| "+cols.join(" | ")+" |\n|"+cols.map(()=>"---").join("|")+"|\n"
   +rows.map(r=>"| "+cols.map(c=>(""+r[c]).replace(/\|/g,"\\|").replace(/\n/g," ")).join(" | ")+" |").join("\n");mime="text/markdown";ext="md";}
 else{const q=s=>'"'+(""+s).replace(/"/g,'""')+'"';
   data=cols.join(",")+"\n"+rows.map(r=>cols.map(c=>q(r[c])).join(",")).join("\n");mime="text/csv";ext="csv";}
 const a=document.createElement("a");
 a.href=URL.createObjectURL(new Blob([data],{type:mime}));
 a.download="results-"+(new Date().toISOString().slice(0,19).replace(/[:T]/g,"-"))+"."+ext;
 a.click();URL.revokeObjectURL(a.href);
}
function logLine(t){
 const l=t.toLowerCase(); let c="";
 if(l.includes("success")||l.includes("[finding]")||l.includes("got through")) c="c-got";
 else if(l.includes("no-service")) c="c-svc";
 else if(l.includes("blocked")||l.includes("control working")||l.includes("held")) c="c-blk";
 else if(l.includes("[warn]")||l.includes("[error]")||l.includes("no-result")||l.includes("auth-failed")||l.includes("detected")) c="c-det";
 else if(t.startsWith("====")||t.startsWith("[")||t.startsWith("Platform")||t.startsWith("Recon")||t.startsWith("Preflight")||t.startsWith("Port policy")) c="c-hdr";
 const d=document.createElement("div"); if(c)d.className=c; d.textContent=t;
 const L=$("#log"); const em=L.querySelector(".empty"); if(em)em.remove();
 L.appendChild(d); L.scrollTop=L.scrollHeight;
}

function startRun(){
 const rows=readTargetRows();
 if(!rows.length){setStatus("No target given — add at least one target row.","err");return;}
 // Each row carries its own posture + net; the NAT ports + creds below apply to any
 // cloud row / to a target that doesn't remember its own.
 const body={rows,module_ids:selectedIds(),
  iterations:+$("#iters").value,workers:+$("#workers").value,wait_unblock:+$("#wait").value,
  ban_expiry:+$("#banexp").value,auto_retry:+$("#autoretry").value,
  site_id:$("#site").value,source:$("#source").value,appliance:$("#appliance").value,
  active:$("#active").checked,debug:$("#debug").checked,confirm_roe:$("#roe").checked,
  smb_port:+$("#smb").value,rpc_port:+$("#rpc").value,ssh_port:+$("#sshp").value,
  creds:{domain:$("#domain").value,dc_user:$("#dcuser").value,dc_pass:$("#dcpass").value,
         ssh_user:$("#sshuser").value,ssh_pass:$("#sshpass").value}};
 fetch("api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
  .then(r=>r.json()).then(j=>{
   if(j.error){setStatus(j.error,"err");return;}
   RUNNING=true;
   COUNTS={};RESN=0;ROWS=[];RUNID=j.run_id;EVRUNS=[];CURTGT=null;PROG={};RUNCFG={};
   $("#resbody").innerHTML="";$("#rowcount").textContent="";
   $("#log").innerHTML="";$("#evidence").textContent="";$("#prog").style.width="0";$("#cmdc").innerHTML="";
   refresh();renderRows();
   $("#runbtn").disabled=true;$("#runbtn").classList.add("running");
   $("#stopbtn").disabled=false;$("#stopbtn").dataset.id=j.run_id;
   stream(j.run_id);
  });
}
function setStatus(txt,cls){const el=$("#runmeta");el.textContent=txt;el.className="statusbar"+(cls?(" "+cls):"");}
function renderSetup(e){
 const d=e.data||{}, host=$("#cmdc"); if(!host) return;
 const kv=(k,v,cls)=> v?`<div class=cmdkv><span class=k>${esc(k)}</span><span class="v${cls?(" "+cls):""}">${esc(v)}</span></div>`:"";
 const card=(t,b)=> b?`<div class=cmdcard><div class=cmdh>${esc(t)}</div><div class=cmdb>${b}</div></div>`:"";
 const sug=d.suggested||[], flt=d.filtered||[], blk=d.expect_block||[];
 let out="";
 out+=card("Environment",
   kv("platform",d.platform)
   +kv("runtime",((d.runtime||[]).join(" · "))+(d.preflight?(" · preflight "+d.preflight):""))
   +kv("evidence",[d.evidence,(d.active?("active "+d.active):""),(d.detections?(d.detections+" detections"):"")].filter(Boolean).join(" · "))
   +kv("source",d.source,"ok"));
 out+=card("Recon"+(d.recon_target?(" · "+d.recon_target):""),
   kv("reachable",d.reachable,"ok")
   +(d.recon_disabled?kv("recon","DISABLED (--no-recon)","warn"):"")
   +kv("suggested",sug.slice(0,6).join(" · ")+(sug.length>6?("   (+"+(sug.length-6)+" more)"):""))
   +kv("canary",d.canary)
   +(flt.length?kv("filtered",flt.length+" not reachable (run anyway)"):""));
 const pc=[d.policy_allowed&&(d.policy_allowed+" allowed"),d.policy_denied&&(d.policy_denied+" denied"),d.policy_na&&(d.policy_na+" n/a")].filter(Boolean).join(" · ");
 out+=card("Policy"+(d.policy_name?(" · "+d.policy_name):""),
   kv("ports",pc)+(blk.length?kv("expect-block",blk.join(" · "),"warn"):""));
 host.innerHTML=out;
}
function stream(id){
 if(ES)ES.close(); ES=new EventSource("api/run/"+id+"/stream");
 ES.onmessage=ev=>{const e=JSON.parse(ev.data);
  if(e.type==="log")logLine(e.line);
  else if(e.type==="setup")renderSetup(e);
  else if(e.type==="status")addRow(e);
  else if(e.type==="progress"){PROG={done:e.done,total:e.total};$("#prog").style.width=(e.total?100*e.done/e.total:0)+"%";renderRunStatus();}
  else if(e.type==="started"){RUNCFG={count:e.count,iters:e.iterations,workers:e.workers,site:e.site_id,active:e.active,
    mode:(e.mode==="auto")?"auto":e.mode,total:(e.targets||[]).length};CURTGT=null;PROG={};renderRunStatus();}
  else if(e.type==="target"){CURTGT={index:e.index,total:e.total,target:e.target,posture:e.posture||"",cloud:!!e.cloud};
    PROG={};$("#prog").style.width="0";$("#cmdc").innerHTML="";renderRunStatus();
    logLine(`\n==== target ${e.index}/${e.total}: ${e.target}`+(e.posture?` · ${e.posture}`:"")+(e.cloud?" · cloud":"")+` ====`);}
  else if(e.type==="target_done")showEvidence(e.root,e.target);
  else if(e.type==="done")finish();
  else if(e.type==="error"){logLine("[error] "+e.error);finish(e.error);}
 };
 ES.onerror=()=>{};
}
// Per-target live status: which target (N/M), its posture, and module progress.
function renderRunStatus(){
 if(!RUNNING) return;
 const c=RUNCFG||{}, t=CURTGT, p=PROG||{};
 let head = t ? ((c.total>1?`[${t.index}/${t.total}] `:"")+t.target+(t.posture?` · ${t.posture}`:"")+(t.cloud?" · cloud":"")) : "starting…";
 const mods = p.total ? `${p.done}/${p.total} modules` : `${c.count||"?"} modules`;
 let tail = [mods, c.mode, (c.iters>1?`${c.iters} iter`:""), (c.workers?`${c.workers} workers`:""), (c.site?`site ${c.site}`:""), (c.active?"active":"")].filter(Boolean).join(" · ");
 setStatus(`${head} · ${tail}`,"run");
}
// Accumulate each target's evidence links so a MULTI-target run shows them all
// (the old code overwrote the strip with the last target only, and omitted att&ck).
function showEvidence(root,target){
 EVRUNS.push({root:String(root).replace(/^evidence\//,""),target:target||""});
 const FMT=[["report.html","report",1],["summary.json","json",1],["summary.csv","csv",0],["summary.xlsx","xlsx",0],["report.txt","txt",1],["attack_navigator_layer.json","att&ck",1]];
 const multi=EVRUNS.length>1;
 $("#evidence").innerHTML="<b>evidence</b> "+EVRUNS.map(ev=>{
  const base="evidence/"+ev.root+"/";
  const links=FMT.map(([f,l,bl])=>`<a ${bl?"target=_blank ":""}href="${base}${f}">${l}</a>`).join("");
  return multi?`<span class=evtgt><i>${esc(ev.target||ev.root)}</i>${links}</span>`:links;
 }).join("");
}
function finish(err){
 RUNNING=false;
 $("#runbtn").disabled=false;$("#runbtn").classList.remove("running");$("#stopbtn").disabled=true;
 const got=Object.entries(COUNTS).filter(([v])=>kindOf(v)==="got").reduce((a,[,n])=>a+n,0);
 if(err){setStatus("run ended with an error — see the live log","err");}
 else{setStatus(got?`run complete — ${got} got through`:"run complete — no findings got through","ok");}
 renderRows();
 if(ES)ES.close(); loadRuns();
}
// Evidence runsbar: ALL runs (never truncated), each self-describing — source ->
// destination, posture (white/black), net (on-prem/cloud) — in three views.
let EV=[], EVVIEW="gallery";
try{ EVVIEW=localStorage.getItem("evview")||"gallery"; }catch(e){}
const EVFMT=[["report.html","report"],["summary.json","json"],["summary.csv","csv"],["summary.xlsx","xlsx"],["report.txt","txt"],["attack_navigator_layer.json","att&ck"]];
async function loadRuns(){
 const j=await (await fetch("api/runs")).json();
 EV=j.runs||[];
 renderEvidence();
}
function evLinks(r){
 const b="evidence/"+r.name+"/";
 return EVFMT.filter(([f])=>r.files[f]).map(([f,l])=>{
   const blank=(f.endsWith(".csv")||f.endsWith(".xlsx"))?"":"target=_blank ";
   const pri=(f==="report.html")?" class=primary":"";
   return `<a ${blank}href="${b}${f}"${pri}>${l}</a>`;}).join("");
}
function evRoute(r){
 const dst=r.target?esc(r.target):"—";
 return r.source?`<span class=src>${esc(r.source)}</span><span class=arrow>→</span><span class=dst>${dst}</span>`
                :`<span class=dst>${dst}</span>`;
}
function evPost(m){ return m?`<span class="pchip ${m[0]==='w'?'w':'b'}">${m[0]==='w'?'white':'black'}</span>`:""; }
function evNet(c){ return c===true?`<span class="nchip cloud">cloud</span>`:(c===false?`<span class="nchip prem">on-prem</span>`:""); }
function evFind(r){ return (r.findings>0)?`<span class=evfind>${r.findings} finding${r.findings>1?'s':''}</span>`
                       :(r.findings===0?`<span class=evclean>clean</span>`:""); }
function renderEvidence(){
 const host=$("#runs"); if(!host) return;
 host.className="runlist "+EVVIEW;
 const cc=$("#runcount"); if(cc) cc.textContent=EV.length?(EV.length+" run"+(EV.length>1?"s":"")):"";
 const sw=$("#evview"); if(sw)[...sw.children].forEach(b=>b.classList.toggle("on",b.dataset.v===EVVIEW));
 if(!EV.length){ host.innerHTML='<div class=nolink>no evidence yet</div>'; return; }
 if(EVVIEW==="table"){ host.innerHTML=evTable(); return; }
 host.innerHTML=EV.map(r=>{
   const status=r.active?`<span class=running>running…</span>`
     :(evLinks(r)?`<span class=rlinks>${evLinks(r)}</span>`:`<span class=nolink>no summary</span>`);
   return `<div class=runrow>`
     +`<div class=rtop><span class=rn>${esc(r.name)}</span>${evFind(r)}</div>`
     +`<div class=rroute>${evRoute(r)} ${evPost(r.mode)} ${evNet(r.cloud)}</div>`
     +`<div class=rfiles>${status}</div></div>`;
 }).join("");
}
function evTable(){
 const dim='<span class=dim>—</span>';
 const head=`<tr><th>Run</th><th>Source</th><th></th><th>Destination</th><th>Posture</th><th>Net</th><th>Findings</th><th>Evidence</th></tr>`;
 const body=EV.map(r=>`<tr>`
   +`<td class=mono>${esc(r.name)}</td>`
   +`<td class=mono>${r.source?esc(r.source):dim}</td>`
   +`<td class=arrowcell>${r.source?'→':''}</td>`
   +`<td class=mono>${r.target?esc(r.target):dim}</td>`
   +`<td>${evPost(r.mode)||dim}</td>`
   +`<td>${evNet(r.cloud)||dim}</td>`
   +`<td>${r.active?'<span class=running>running…</span>':(r.findings>0?`<span class=evfind>${r.findings}</span>`:(r.findings===0?'<span class=evclean>0</span>':dim))}</td>`
   +`<td class=evlinks>${r.active?'':(evLinks(r)||dim)}</td>`
 +`</tr>`).join("");
 return `<table class=evtable><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

$("#roe").addEventListener("change",syncRoe);
$$("[data-preset]").forEach(b=>b.addEventListener("click",()=>applyPreset(b.dataset.preset)));
$("#runbtn").addEventListener("click",startRun);
$("#stopbtn").addEventListener("click",()=>fetch("api/run/"+$("#stopbtn").dataset.id+"/stop",{method:"POST"}));
$("#evview").addEventListener("click",e=>{const b=e.target.closest("button");if(!b||!b.dataset.v)return;
 EVVIEW=b.dataset.v; try{localStorage.setItem("evview",EVVIEW);}catch(e){} renderEvidence();});
// --- three-way tab switch (Results / Live log / History) ---
const TABS=[["#tabRes","#paneRes"],["#tabLog","#paneLog"],["#tabHist","#paneHist"]];
function showTab(tab){TABS.forEach(([t,p])=>{const on=(t===tab);
  $(t).classList.toggle("on",on);$(t).setAttribute("aria-selected",on?"true":"false");$(p).classList.toggle("hidden",!on);});
  if(tab==="#tabHist") loadHistory();}
TABS.forEach(([t])=>$(t).addEventListener("click",()=>showTab(t)));
// listen for BOTH input (typing in #fq) and change (a <select> firing change on
// selection — not all browsers emit input for <select>, which broke filter-by-IP).
["#fq","#fverdict","#fcat","#ftarget"].forEach(s=>["input","change"].forEach(ev=>$(s).addEventListener(ev,()=>renderRows())));
$$("#restable thead th").forEach(th=>th.addEventListener("click",()=>{
 const c=th.dataset.col; if(!c)return;
 SORT.dir=(SORT.col===c)?-SORT.dir:1; SORT.col=c; renderRows();}));
$$("#paneRes .exp button").forEach(b=>b.addEventListener("click",()=>exportRows(b.dataset.exp)));
$("#dclose").addEventListener("click",closeDrawer);
$("#scrim").addEventListener("click",closeDrawer);
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();});

// --- History: cross-run query over the SQLite index (derived from evidence/) ---
let HROWS=[], HSORT={col:"ts",dir:-1};
async function loadHistory(){
 const p=new URLSearchParams();
 const q=$("#hq").value.trim(); if(q)p.set("q",q);
 if($("#hverdict").value)p.set("verdict",$("#hverdict").value);
 if($("#htarget").value)p.set("target_ip",$("#htarget").value);
 if($("#hsite").value)p.set("site_id",$("#hsite").value);
 p.set("limit","2000");
 $("#histbody").innerHTML="<tr><td colspan=9 class=dim>loading…</td></tr>";
 try{
  const j=await (await fetch("api/query?"+p.toString())).json();
  if(j.error){$("#histbody").innerHTML="<tr><td colspan=9 class=dim>"+esc(j.error)+"</td></tr>";return;}
  HROWS=j.rows||[]; renderHistRoll(j.stats||{}); syncHistFilters(j.stats||{}); renderHist();
 }catch(err){$("#histbody").innerHTML="<tr><td colspan=9 class=dim>error: "+esc(""+err)+"</td></tr>";}
}
function renderHistRoll(stats){
 const o=stats.overall||{};
 $("#histroll").innerHTML=(BOOT.verdict_order||[]).filter(v=>o[v]).map(v=>{
  const c=vcolor(v);
  return `<span class=hr><i style="background:${c}"></i>${esc(v)} <b>${o[v]}</b></span>`;}).join("")
  +` <span class="hr runs"><i></i>runs <b>${stats.runs||0}</b></span>`;
}
function syncHistFilters(stats){
 const add=(sel,vals)=>{const cur=sel.value,have=new Set([...sel.options].map(o=>o.value));
  [...vals].filter(Boolean).sort().forEach(v=>{if(!have.has(v)){const o=document.createElement("option");o.value=o.textContent=v;sel.appendChild(o);}});sel.value=cur;};
 add($("#hverdict"), new Set(HROWS.map(r=>r.verdict)));
 add($("#htarget"),  new Set(HROWS.map(r=>r.target_ip)));
 add($("#hsite"),    new Set(HROWS.map(r=>r.site_id)));
}
function renderHist(){
 const rows=HROWS.slice(), c=HSORT.col, d=HSORT.dir;
 rows.sort((a,b)=>{let x=(""+(a[c]||"")).toLowerCase(),y=(""+(b[c]||"")).toLowerCase();return x<y?-d:x>y?d:0;});
 const tb=$("#histbody"); tb.innerHTML="";
 rows.forEach(r=>{const col=vcolor(r.verdict);
  const tr=document.createElement("tr");
  tr.innerHTML=`<td class=mono>${esc((r.ts||"").replace("T"," ").slice(5,19))}</td>`
   +`<td><span class=vchip style="color:${col}"><span class=d></span><span class=t>${esc(r.verdict)}</span></span></td>`
   +`<td class=mono>${esc(r.target_ip)}</td><td>${esc(r.attack)}</td><td class=dim>${esc(r.category)}</td>`
   +`<td class=mono>${esc(r.mitre)}</td><td class=mono>${esc(r.cwe)}</td>`
   +`<td class=mono>${esc(r.site_id||"")}</td><td class=mono title="${esc(r.run_id)}">${esc((r.run_id||"").replace(/^run_/,""))}</td>`;
  tb.appendChild(tr);});
 $("#histcount").textContent=rows.length+" rows";
 $$("#histtable thead th").forEach(th=>{const a=th.querySelector(".ar"); if(a)a.remove();
  if(th.dataset.hcol===HSORT.col){const s=document.createElement("span");s.className="ar";s.textContent=HSORT.dir>0?"▲":"▼";th.appendChild(s);}});
}
["#hq","#hverdict","#htarget","#hsite"].forEach(s=>["input","change"].forEach(ev=>$(s).addEventListener(ev,loadHistory)));
$$("#histtable thead th").forEach(th=>th.addEventListener("click",()=>{
 const c=th.dataset.hcol; if(!c)return; HSORT.dir=(HSORT.col===c)?-HSORT.dir:1; HSORT.col=c; renderHist();}));
$("#reindex").addEventListener("click",async()=>{
 $("#reindex").textContent="reindexing…";
 try{await fetch("api/reindex",{method:"POST"});}catch(e){}
 $("#reindex").textContent="reindex"; loadHistory();});
$$("#paneHist [data-hexp]").forEach(b=>b.addEventListener("click",()=>{
 const cols=["ts","verdict","target_ip","attack","category","mitre","cwe","site_id","run_id"];
 let data,ext;
 if(b.dataset.hexp==="json"){data=JSON.stringify(HROWS,null,1);ext="json";}
 else{const qq=s=>'"'+(""+(s==null?"":s)).replace(/"/g,'""')+'"';
   data=cols.join(",")+"\n"+HROWS.map(r=>cols.map(c=>qq(r[c])).join(",")).join("\n");ext="csv";}
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([data],{type:"text/"+ext}));
 a.download="history-"+Date.now()+"."+ext;a.click();URL.revokeObjectURL(a.href);}));
boot();
