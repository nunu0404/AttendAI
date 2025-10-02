async function fetchSessions(){
  const r = await fetch('/api/sessions'); if(!r.ok) return []
  const j = await r.json(); return j.sessions || []
}
async function fetchCurrentSessionId(){
  const r = await fetch('/api/session/current'); if(!r.ok) return null
  const j = await r.json(); return j.session_id
}
function selectedSessionId(){
  const sel = document.getElementById('sessionSel')
  return sel && sel.value ? parseInt(sel.value,10) : null
}
async function initSessionSelect(){
  const sel = document.getElementById('sessionSel')
  if(!sel) return
  const list = await fetchSessions()
  sel.innerHTML = ''
  let cur = await fetchCurrentSessionId()
  list.forEach(s=>{
    const o = document.createElement('option')
    const st = s.start_time
    const et = s.end_time
    o.value = s.id
    o.textContent = `${st} ~ ${et}`
    sel.appendChild(o)
  })
  if(cur){
    const opt = Array.from(sel.options).find(o=>parseInt(o.value,10)===cur)
    if(opt) sel.value = String(cur)
  }
  sel.addEventListener('change', refreshAll)
}
async function loadStats(sid){
  const r = await fetch('/api/attendance/session/'+sid+'/stats'); if(!r.ok) return
  const j = await r.json()
  document.getElementById('stats').innerText = '총 로그: '+j.total_logs+'명, 고유 학생: '+j.unique_students+'명'
}
async function loadAnomaly(sid){
  const r = await fetch('/api/anomaly/session/'+sid); if(!r.ok) return
  const j = await r.json()
  const tb = document.querySelector('#tbl tbody'); tb.innerHTML = ''
  j.results.forEach(x=>{
    const tr = document.createElement('tr')
    const td1 = document.createElement('td'); td1.textContent = x.student_id
    const td2 = document.createElement('td'); td2.textContent = x.score
    const td3 = document.createElement('td'); td3.textContent = x.flags.join(',')
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tb.appendChild(tr)
  })
}
async function loadExcuses(sid){
  const r = await fetch('/api/excuses/session/'+sid); if(!r.ok) return
  const j = await r.json()
  const tb = document.querySelector('#excuses tbody'); tb.innerHTML = ''
  j.excuses.forEach(x=>{
    const tr = document.createElement('tr')
    const td1 = document.createElement('td'); td1.textContent = x.student_id
    const td2 = document.createElement('td'); td2.textContent = x.excuse_type
    const td3 = document.createElement('td'); td3.textContent = x.evidence_ok ? '확인' : '미확인'
    const td4 = document.createElement('td'); td4.textContent = x.notes || ''
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4); tb.appendChild(tr)
  })
}
async function loadLogs(sid){
  const r = await fetch('/api/attendance/session/'+sid+'/list'); if(!r.ok) return
  const j = await r.json()
  const tb = document.querySelector('#logs tbody'); tb.innerHTML = ''
  j.logs.forEach(x=>{
    const tr = document.createElement('tr')
    const td1 = document.createElement('td'); td1.textContent = x.student_id
    const td2 = document.createElement('td'); td2.textContent = x.checked_at
    const td3 = document.createElement('td'); td3.textContent = x.device_name || ''
    const td4 = document.createElement('td'); td4.textContent = x.ip || ''
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4); tb.appendChild(tr)
  })
}
async function refreshAll(){
  const sid = selectedSessionId(); if(!sid) return
  await loadStats(sid)
  await loadAnomaly(sid)
  await loadExcuses(sid)
  await loadLogs(sid)
}
async function ingestGmail(){
  const btn = document.getElementById('btnGmail')
  const st = document.getElementById('gmailStatus')
  if(btn) btn.disabled = true
  if(st) st.textContent = '수집 중...'
  try{
    const r = await fetch('/api/excuses/gmail/ingest', {method:'POST'})
    if(st) st.textContent = r.ok ? '완료' : '실패'
    await refreshAll()
  }catch(e){
    if(st) st.textContent = '에러'
  }finally{
    if(btn) btn.disabled = false
    setTimeout(()=>{ if(st) st.textContent='' }, 3000)
  }
}
document.addEventListener('DOMContentLoaded', async ()=>{
  await initSessionSelect()
  const btnG = document.getElementById('btnGmail')
  if(btnG) btnG.addEventListener('click', ingestGmail)
  const btnA = document.getElementById('btnCsvAttendance')
  if(btnA) btnA.addEventListener('click', async ()=>{
    const sid = selectedSessionId(); if(!sid) return
    window.open('/api/export/session/'+sid+'/attendance.csv','_blank')
  })
  const btnE = document.getElementById('btnCsvExcuses')
  if(btnE) btnE.addEventListener('click', async ()=>{
    const sid = selectedSessionId(); if(!sid) return
    window.open('/api/export/session/'+sid+'/excuses.csv','_blank')
  })
  await refreshAll()
  setInterval(refreshAll, 4000)
})
