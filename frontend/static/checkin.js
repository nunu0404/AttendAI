function qp(k){ let u=new URL(window.location.href); return u.searchParams.get(k) }

function loadDeviceId(){
  let id = localStorage.getItem('attendai_device')
  if(id) return id
  const s = navigator.userAgent + '|' + (navigator.platform||'') + '|' + screen.width+'x'+screen.height + '|' + Date.now() + '|' + Math.random()
  // 간단 해시
  let h = 0
  for (let i=0;i<s.length;i++){ h = ((h<<5)-h) + s.charCodeAt(i); h |= 0 }
  id = 'dev-' + Math.abs(h)
  localStorage.setItem('attendai_device', id)
  return id
}

let cur = { sid: null, token: null, valid_until: null }
async function fetchCurrentQR(){
  let r = await fetch('/api/qr/current')
  if(!r.ok) return null
  let j = await r.json()
  cur.sid = j.session_id
  cur.token = j.token
  cur.valid_until = j.valid_until
  return cur
}
async function init(){
  let s = qp('session_id')
  if(!s){
    let r = await fetch('/api/session/current')
    if(r.ok){ let j = await r.json(); cur.sid = j.session_id }
  }else{
    cur.sid = s
  }
  await fetchCurrentQR()
  document.getElementById('session_id').value = cur.sid || ''
  document.getElementById('token').value = cur.token || ''
}

document.getElementById('f').addEventListener('submit', async (e)=>{
  e.preventDefault()
  let latest = await fetchCurrentQR()
  let sid = latest && latest.sid ? latest.sid : cur.sid
  let token = latest && latest.token ? latest.token : cur.token
  let device = loadDeviceId()

  let body = {
    session_id: sid,
    student_id: document.getElementById('student_id').value,
    token: token,
    device_name: device
  }
  let r = await fetch('/api/attendance/check-in', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body)
  })
  let m = document.getElementById('msg')
  if(r.ok){ m.innerText = '출석 완료' }
  else{ m.innerText = '실패: ' + (await r.text()) }
})

setInterval(fetchCurrentQR, 4000)
init()
