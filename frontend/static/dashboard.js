// ===== 대시보드 JS (공결 표 숨기고 CSV만 유지 버전) =====
const ALL_DAYS = 30; // '전체' 모드 기간

async function fetchSessions(){
  const r = await fetch('/api/sessions'); if(!r.ok) return [];
  const j = await r.json(); return j.sessions || [];
}
function selectedSessionId(){
  const sel = document.getElementById('sessionSel');
  return sel && sel.value ? sel.value : null; // 문자열 그대로 보존
}

async function initSessionSelect(){
  const sel = document.getElementById('sessionSel');
  if(!sel) return;

  const list = await fetchSessions();
  sel.innerHTML = '';

  // '전체' 옵션(최근 ALL_DAYS일)
  const all = document.createElement('option');
  all.value = 'all';
  all.textContent = `전체 (최근 ${ALL_DAYS}일)`;
  sel.appendChild(all);

  // 세션 목록
  list.forEach(s=>{
    const o = document.createElement('option');
    o.value = String(s.id);
    o.textContent = `${s.start_time} ~ ${s.end_time}`;
    sel.appendChild(o);
  });

  sel.value = 'all';
  sel.addEventListener('change', refreshAll);
}

// --- 출석 관련 렌더링만 유지 ---
async function loadStats(sid){
  const r = await fetch('/api/attendance/session/'+sid+'/stats'); if(!r.ok) return;
  const j = await r.json();
  const el = document.getElementById('stats');
  if (el) el.innerText = `총 로그: ${j.total_logs}명, 고유 학생: ${j.unique_students}명`;
}
async function loadAnomaly(sid){
  const r = await fetch('/api/anomaly/session/'+sid); if(!r.ok) return;
  const j = await r.json();
  const tb = document.querySelector('#tbl tbody'); if(!tb) return;
  tb.innerHTML = '';
  (j.results || []).forEach(x=>{
    const tr = document.createElement('tr');
    const td1 = document.createElement('td'); td1.textContent = x.student_id;
    const td2 = document.createElement('td'); td2.textContent = x.score;
    const td3 = document.createElement('td'); td3.textContent = (x.flags||[]).join(',');
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
    tb.appendChild(tr);
  });
}
async function loadLogs(sid){
  const tb = document.querySelector('#logs tbody'); if(!tb) return;
  tb.innerHTML = '';
  let list = [];
  if (sid === 'all') {
    const r = await fetch(`/api/attendance/recent?days=${ALL_DAYS}&limit=50`); if(!r.ok) return;
    const j = await r.json(); list = j.logs || [];
  } else {
    const r = await fetch('/api/attendance/session/'+sid+'/list'); if(!r.ok) return;
    const j = await r.json(); list = j.logs || [];
  }
  list.slice(0,5).forEach(x=>{
    const tr = document.createElement('tr');
    const td1 = document.createElement('td'); td1.textContent = x.student_id;
    const td2 = document.createElement('td'); td2.textContent = x.checked_at;
    const td3 = document.createElement('td'); td3.textContent = x.device_name || '';
    const td4 = document.createElement('td'); td4.textContent = x.ip || '';
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
    tb.appendChild(tr);
  });
}

async function refreshAll(){
  const sid = selectedSessionId(); if(!sid) return;

  if (sid === 'all') {
    // '전체' 모드: 출석만
    await loadLogs('all');
    const s = document.getElementById('stats'); if (s) s.textContent = '';
    const tb = document.querySelector('#tbl tbody'); if (tb) tb.innerHTML = '';
    return;
  }

  await loadStats(sid);
  await loadAnomaly(sid);
  await loadLogs(sid);
}

// --- Gmail 크롤링 버튼: 수집은 하되 화면에 공결 표시는 생략 ---
async function ingestGmail(){
  const btn = document.getElementById('btnGmail');
  const st = document.getElementById('gmailStatus');
  if(btn) btn.disabled = true;
  if(st) st.textContent = '수집 중...';
  try{
    const r = await fetch('/api/excuses/gmail/ingest?days=30&query=', {method:'POST'});
    if(st) st.textContent = r.ok ? '완료' : '실패';
    // 공결 표시는 하지 않음. 출석만 새로고침
    await refreshAll();
  }catch(e){
    if(st) st.textContent = '에러';
  }finally{
    if(btn) btn.disabled = false;
    setTimeout(()=>{ if(st) st.textContent='' }, 3000);
  }
}

document.addEventListener('DOMContentLoaded', async ()=>{
  await initSessionSelect();

  const btnG = document.getElementById('btnGmail');
  if(btnG) btnG.addEventListener('click', ingestGmail);

  // 출석 CSV
  const btnA = document.getElementById('btnCsvAttendance');
  if(btnA) btnA.addEventListener('click', ()=>{
    const sid = selectedSessionId(); if(!sid) return;
    if (sid === 'all') window.open(`/api/export/attendance/recent.csv?days=${ALL_DAYS}`,'_blank');
    else window.open('/api/export/session/'+sid+'/attendance.csv','_blank');
  });

  // 공결 CSV (표시는 안하지만 CSV는 제공)
  const btnE = document.getElementById('btnCsvExcuses');
  if(btnE) btnE.addEventListener('click', ()=>{
    const sid = selectedSessionId(); if(!sid) return;
    if (sid === 'all') window.open(`/api/export/excuses/recent.csv?days=${ALL_DAYS}&enc=cp949`,'_blank');
    else window.open('/api/export/session/'+sid+'/excuses.csv?enc=cp949','_blank');
  });

  await refreshAll();
  setInterval(refreshAll, 4000);
});

// ===== QR 팝업 + 대체 모달 =====
let qrWin = null;

function openQrPopup() {
  // 1) 사용자 클릭 직후 동기적으로 빈 창 먼저
  const w = 520, h = 740;
  const left = Math.max(0, (screen.width - w) / 2);
  const top  = Math.max(0, (screen.height - h) / 2);
  const feat = `popup=yes,width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=no`;

  // 빈 창 오픈 (차단되면 null/undefined 또는 즉시 closed)
  qrWin = window.open('about:blank', 'AttendAI_QR', feat);

  if (!qrWin || qrWin.closed) {
    // 팝업 차단: 대체 모달로 전환
    showQrFallback();
    return false;
  }

  try { qrWin.document.title = 'AttendAI - QR'; } catch(e) {}
  try { qrWin.focus(); } catch(e) {}

  // 2) 같은 오리진 QR 페이지로 이동
  const base = window.location.origin; // http(s)://127.0.0.1:8000
  try { qrWin.location.href = `${base}/`; } catch(e) {
    // 혹시 location 변경이 막히면 대체 모달로
    try { qrWin.close(); } catch(_) {}
    showQrFallback();
    return false;
  }
  return true;
}

function closeQrPopup() {
  // 팝업 닫기
  if (qrWin && !qrWin.closed) {
    try { qrWin.close(); } catch(e) {}
  }
  qrWin = null;
  // 대체 모달 닫기
  hideQrFallback();
}

function showQrFallback() {
  const layer = document.getElementById('qrFallback');
  const frame = document.getElementById('qrFallbackFrame');
  if (!layer || !frame) return;
  frame.src = `${window.location.origin}/`;
  layer.classList.remove('hidden');
}

function hideQrFallback() {
  const layer = document.getElementById('qrFallback');
  const frame = document.getElementById('qrFallbackFrame');
  if (!layer || !frame) return;
  frame.src = 'about:blank';
  layer.classList.add('hidden');
}

// 버튼 핸들러 등록 (최종 우선 순위로)
document.addEventListener('DOMContentLoaded', () => {
  const btnStart = document.getElementById('btnStartAttendance');
  const btnStop  = document.getElementById('btnStopAttendance');
  const btnClose = document.getElementById('qrFallbackClose');

  if (btnStart) {
    btnStart.addEventListener('click', (e) => {
      // 절대 await/fetch 먼저 하지 말고, 즉시 open
      openQrPopup();
    });
  }
  if (btnStop) {
    btnStop.addEventListener('click', (e) => {
      closeQrPopup();
    });
  }
  if (btnClose) {
    btnClose.addEventListener('click', hideQrFallback);
  }
});


// ===== 끝 =====
