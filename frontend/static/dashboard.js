let qrWindow = null;
const qrChan = new BroadcastChannel('qr-control');

async function fetchSessions(){
  const r = await fetch('/api/sessions'); if(!r.ok) return [];
  const j = await r.json(); return j.sessions || [];
}
async function fetchCurrentSessionId(){
  const r = await fetch('/api/session/current'); if(!r.ok) return null;
  const j = await r.json(); return j.session_id;
}
function selectedSessionId(){
  const sel = document.getElementById('sessionSel');
  return sel && sel.value ? parseInt(sel.value,10) : null;
}
async function ensureSessionId(){
  let sid = selectedSessionId();
  if(!sid){
    sid = await fetchCurrentSessionId();
    const sel = document.getElementById('sessionSel');
    if(sel && sid) sel.value = String(sid);
  }
  return sid;
}

async function initSessionSelect(){
  const sel = document.getElementById('sessionSel');
  if(!sel) return;
  const list = await fetchSessions();
  sel.innerHTML = '';
  const cur = await fetchCurrentSessionId();
  list.forEach(s=>{
    const o = document.createElement('option');
    o.value = s.id;
    o.textContent = `${s.start_time} ~ ${s.end_time}`;
    sel.appendChild(o);
  });
  if(cur){
    const opt = Array.from(sel.options).find(o=>parseInt(o.value,10)===cur);
    if(opt) sel.value = String(cur);
  }
  sel.addEventListener('change', refreshAll);
}

async function loadStats(sid){
  const r = await fetch('/api/attendance/session/'+sid+'/stats'); if(!r.ok) return;
  const j = await r.json();
  document.getElementById('stats').innerText =
    `총 로그: ${j.total_logs}명, 고유 학생: ${j.unique_students}명`;
}
async function loadAnomaly(sid){
  const r = await fetch('/api/anomaly/session/'+sid); if(!r.ok) return;
  const j = await r.json();
  const tb = document.querySelector('#tbl tbody'); if(!tb) return;
  tb.innerHTML = '';
  j.results.forEach(x=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${x.student_id}</td><td>${x.score}</td><td>${x.flags.join(',')}</td>`;
    tb.appendChild(tr);
  });
}
async function loadExcuses(sid){
  const r = await fetch('/api/excuses/session/'+sid); if(!r.ok) return;
  const j = await r.json();
  const tb = document.querySelector('#excuses tbody'); if(!tb) return;
  tb.innerHTML = '';
  j.excuses.forEach(x=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${x.student_id}</td><td>${x.excuse_type}</td><td>${x.evidence_ok?'확인':'미확인'}</td><td>${x.notes||''}</td>`;
    tb.appendChild(tr);
  });
}
async function loadLogs(sid){
  const r = await fetch('/api/attendance/session/'+sid+'/list'); if(!r.ok) return;
  const j = await r.json();
  const tb = document.querySelector('#logs tbody'); if(!tb) return;
  tb.innerHTML = '';
  j.logs.forEach(x=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${x.student_id}</td><td>${x.checked_at}</td><td>${x.device_name||''}</td><td>${x.ip||''}</td>`;
    tb.appendChild(tr);
  });
}
async function refreshAll(){
  const sid = await ensureSessionId(); if(!sid) return;
  await loadStats(sid);
  await loadAnomaly(sid);
  await loadExcuses(sid);
  await loadLogs(sid);
}

/* 시작/종료 버튼: 서버 API 없이 팝업만 제어 */
function setCheckinButtons(active){
  const s = document.getElementById('btnCheckinStart');
  const e = document.getElementById('btnCheckinStop');
  if(s) s.disabled = !!active;
  if(e) e.disabled = !active;
}
async function checkinStart(){
  const sid = selectedSessionId(); if(!sid){ alert('세션을 선택하세요.'); return; }

  // 이전 핸들은 버리고, 항상 새 창을 띄운다 (팝업 차단 시 null 반환)
  const w = window.open(`/?session_id=${sid}`, '_blank', 'width=480,height=640');
  if (!w) {
    alert('브라우저가 팝업을 차단했습니다. 이 사이트의 팝업을 허용해 주세요.');
    return;
  }
  qrWindow = w;
  try { w.focus(); } catch(_) {}

  // (버튼 상태 토글이 있으면 호출)
  // setCheckinButtons(true);
}

async function checkinStop(){
  // 1) 직접 닫기 시도
  try { if (qrWindow && !qrWindow.closed) qrWindow.close(); } catch(_) {}
  qrWindow = null;

  // 2) 혹시 닫히지 않았을 때를 대비해 QR창에 "스스로 닫아라" 신호
  try { qrChan.postMessage({ op: 'stop' }); } catch(_) {}

  // setCheckinButtons(false);
}

/* Gmail 수집 */
async function ingestGmail(){
  const btn = document.getElementById('btnGmail');
  const st  = document.getElementById('gmailStatus');
  const sid = selectedSessionId();
  if(btn) btn.disabled = true;
  if(st)  st.textContent = '수집 중...';
  try{
    // 최근 3일, 쿼리 없음(전체)
    const r = await fetch('/api/excuses/gmail/ingest?days=3&query=', {method:'POST'});
    if(!r.ok){ if(st) st.textContent = '실패'; return; }
    if(st) st.textContent = '완료';
    await refreshAll();
  }catch(_){
    if(st) st.textContent = '에러';
  }finally{
    if(btn) btn.disabled = false;
    setTimeout(()=>{ if(st) st.textContent=''; }, 2000);
  }
}


/* CSV 다운로드 */
function downloadAttendanceCsv(){
  ensureSessionId().then(sid=>{
    if(!sid){ alert('세션이 없습니다.'); return; }
    window.open('/api/export/session/'+sid+'/attendance.csv','_blank');
  });
}
function downloadExcusesCsv(){
  ensureSessionId().then(sid=>{
    if(!sid){ alert('세션이 없습니다.'); return; }
    window.open('/api/export/session/'+sid+'/excuses.csv','_blank');
  });
}

document.addEventListener('DOMContentLoaded', async ()=>{
  await initSessionSelect();
  const btnStart = document.getElementById('btnCheckinStart');
  const btnStop  = document.getElementById('btnCheckinStop');
  const btnG     = document.getElementById('btnGmail');
  const btnA     = document.getElementById('btnCsvAttendance');
  const btnE     = document.getElementById('btnCsvExcuses');

  if(btnStart) btnStart.addEventListener('click', checkinStart);
  if(btnStop)  btnStop.addEventListener('click', checkinStop);
  if(btnG)     btnG.addEventListener('click', ingestGmail);
  if(btnA)     btnA.addEventListener('click', downloadAttendanceCsv);
  if(btnE)     btnE.addEventListener('click', downloadExcusesCsv);

  await refreshAll();
  setCheckinButtons(false);
  setInterval(refreshAll, 4000);
});
