let sid=0,remaining=0;async function refresh(){let r=await fetch('/api/qr/current');if(!r.ok)return;let j=await r.json();sid=j.session_id;let img=document.getElementById('qrimg');img.src='/api/qr/image?session_id='+sid+'&_='+(Date.now());let vu=new Date(j.valid_until.replace(' ','T'));let now=new Date();remaining=Math.max(0,Math.floor((vu-now)/1000));document.getElementById('timer').innerText='남은 시간: '+remaining+'초'};setInterval(async()=>{remaining--;if(remaining<=0){await refresh()}else{document.getElementById('timer').innerText='남은 시간: '+remaining+'초'}},1000);refresh();

try {
  const ch = new BroadcastChannel('qr-control');
  ch.onmessage = (e)=>{ if(e?.data?.op === 'stop') window.close(); };
} catch(_){}