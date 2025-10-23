// ---------- helpers ----------
async function getJSON(url) {
  const r = await fetch(url, {credentials:"same-origin"});
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function postJSON(url, body={}) {
  const r = await fetch(url, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
function $(id){ return document.getElementById(id); }
function opt(text,val){ const o=document.createElement("option"); o.textContent=text; o.value=val; return o; }
function msg(e){ try{return JSON.stringify(e);}catch{ return String(e);} }

// ---------- state ----------
let currentSid = null;
let qrTickTimer = null;      // 1s 카운트다운
let qrCountdown = 15;
let lastQrToken = null;

let logsPollTimer = null;    // 출석 로그 자동 갱신(최근 5명)

// ---------- entry ----------
window.addEventListener("DOMContentLoaded", async () => {
  $("btnStart").addEventListener("click", onStartSession);
  $("btnStop").addEventListener("click", onStopSession);
  $("btnGmail").addEventListener("click", onGmail);
  $("btnCSV").addEventListener("click", onCSV);
  $("btnCSVExcuse").addEventListener("click", onCSVExcuse);
  $("btnAnalyze").addEventListener("click", onAnalyze);
  $("sessionSel").addEventListener("change", async () => {
    currentSid = parseInt($("sessionSel").value,10);
    stopQrLoop();
    stopLogsPolling();
    await refreshAll();      // 표 초기 로드
  });

  await loadSessions();
  await refreshAll();        // 표 초기 로드
});

// ---------- sessions ----------
async function loadSessions(){
  const data = await getJSON("/api/sessions");
  const sel = $("sessionSel");
  sel.innerHTML = "";
  (data.sessions || []).forEach(s=>{
    sel.appendChild(opt(`#${s.id} : ${s.start_time} ~ ${s.end_time}`, s.id));
  });
  if (sel.options.length){ sel.selectedIndex = 0; currentSid = parseInt(sel.value,10); }
  else currentSid = null;
}

// ---------- tables ----------
async function refreshAll(){
  if (!currentSid){
    $("hint").textContent = "세션을 시작해 주세요.";
    clearTable("logsTbl");
    clearTable("excuseTbl");
    clearTable("susTbl");
    return;
  }
  $("hint").textContent = `세션 선택 (#${currentSid})`;

  // 공결
  try{
    const d = await getJSON(`/api/excuses/session/${currentSid}`);
    const tb = $("excuseTbl").querySelector("tbody");
    tb.innerHTML="";
    (d.excuses||[]).forEach(r=>{
      const tr=document.createElement("tr");
      tr.innerHTML = `<td>${r.student_id}</td><td>${r.excuse_type}</td><td>${r.evidence_ok?"O":"X"}</td><td>${r.notes||""}</td>`;
      tb.appendChild(tr);
    });
  }catch(e){ console.warn(e); }

  // 최근 5명 로그 1회 로드 + 폴링 시작(출석 여부 확인 용)
  await refreshRecentLogs();
  startLogsPolling();
}

function clearTable(id){ $(id).querySelector("tbody").innerHTML=""; }

// 최근 5명만 표시(최신이 위)
async function refreshRecentLogs(){
  if (!currentSid) return;
  try{
    const d = await getJSON(`/api/attendance/session/${currentSid}/list`);
    const all = (d.logs || []);
    const recent = all.slice(-5).reverse(); // 최신이 먼저 보이게
    const tb = $("logsTbl").querySelector("tbody");
    tb.innerHTML = "";
    recent.forEach(r=>{
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${r.student_id}</td><td>${r.checked_at}</td><td>${r.device_name||""}</td><td>${r.ip||""}</td>`;
      tb.appendChild(tr);
    });
  }catch(e){
    // 세션 없을 때 404가 올 수 있으므로 콘솔만
    console.warn(e);
  }
}

function startLogsPolling(){
  stopLogsPolling();
  // 3초마다 최근 5명 갱신
  logsPollTimer = setInterval(refreshRecentLogs, 3000);
}
function stopLogsPolling(){
  if (logsPollTimer){ clearInterval(logsPollTimer); logsPollTimer=null; }
}

// ---------- QR ----------
function stopQrLoop(){
  if (qrTickTimer){ clearInterval(qrTickTimer); qrTickTimer=null; }
  $("qrBox").style.display="none";
  $("btnStop").style.display="none";
  lastQrToken=null;
}

async function startQrLoop(){
  if (!currentSid) return;
  $("qrBox").style.display="flex";
  $("btnStop").style.display="inline-block";

  const updateQR = async () => {
    try{
      const cur = await getJSON(`/api/qr/current?session_id=${currentSid}`);
      lastQrToken = cur.token;
      $("qrMeta").textContent = `세션 #${cur.session_id} · 생성: ${cur.generated_at} · 만료: ${cur.valid_until}`;
      $("qrImg").src = `/api/qr/image?session_id=${currentSid}&_=${Date.now()}`; // 캐시 방지
      qrCountdown = 15;
      $("qrCountdown").textContent = qrCountdown;
    }catch(e){
      console.error(e);
      $("qrMeta").textContent = "QR 생성 실패";
    }
  };

  await updateQR();

  // 1초 카운트다운 + 15초마다 실제 갱신
  if (qrTickTimer) clearInterval(qrTickTimer);
  qrTickTimer = setInterval(async ()=>{
    qrCountdown -= 1;
    if (qrCountdown <= 0){
      await updateQR();
      await refreshRecentLogs(); // 갱신 타이밍에 표도 한 번 동기화
    } else {
      $("qrCountdown").textContent = qrCountdown;
    }
  }, 1000);

  // 출석 중에는 폴링 확실히 가동
  startLogsPolling();
}

// ---------- actions ----------
async function onStartSession(){
  try{
    const res = await postJSON("/api/session/start", {hours:2});
    await loadSessions();
    [...$("sessionSel").options].forEach((o,i)=>{ if (parseInt(o.value,10)===res.session_id) $("sessionSel").selectedIndex=i; });
    currentSid = res.session_id;
    $("hint").textContent = `세션 시작 (#${currentSid})`;
    await refreshAll();
    await startQrLoop();
  }catch(e){ alert(msg(e)); }
}

async function onStopSession(){
  try{
    try{ await postJSON(`/api/qr/stop?session_id=${currentSid}`, {}); }catch(_){}
  }finally{
    stopQrLoop();
    stopLogsPolling();
  }
}

async function onGmail(){
  try{
    $("btnGmail").disabled = true;
    const res = await postJSON(`/api/excuses/gmail/ingest?days=30&query=${encodeURIComponent("")}`, {});
    alert(`Gmail 처리 완료\nfound: ${res.found}\nupserted: ${res.upserted}\nsid_missing: ${res.sid_missing}`);
    await refreshAll();
  }catch(e){ alert(msg(e)); }
  finally{ $("btnGmail").disabled = false; }
}

function onCSV(){
  if (!currentSid) return alert("세션을 선택하세요.");
  window.open(`/api/export/session/${currentSid}/attendance.csv`,"_blank");
}
function onCSVExcuse(){
  if (!currentSid) return alert("세션을 선택하세요.");
  window.open(`/api/export/session/${currentSid}/excuses.csv`,"_blank");
}

async function onAnalyze(){
  if (!currentSid) return alert("세션을 선택하세요.");
  try{
    const res = await getJSON(`/api/anomaly/session/${currentSid}`);
    const tb = $("susTbl").querySelector("tbody");
    tb.innerHTML="";
    (res.results||[]).forEach(r=>{
      if (!r.flags || !r.flags.length) return;
      const tr=document.createElement("tr");
      tr.innerHTML = `<td>${r.student_id}</td><td>${r.flags.join(", ")}</td>`;
      tb.appendChild(tr);
    });
    alert("분석 완료");
  }catch(e){ alert(msg(e)); }
}
