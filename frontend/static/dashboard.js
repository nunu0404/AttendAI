// ---------- helpers ----------
async function getJSON(url) {
  const r = await fetch(url, { credentials: "same-origin" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function postJSON(url, body = {}) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function deleteJSON(url) {
  const r = await fetch(url, {
    method: "DELETE",
    headers: { "Content-Type": "application/json" }
  });
  let data = null;
  try { data = await r.json(); } catch {}
  if (!r.ok) {
    const err = (data && (data.detail || data.error)) || r.statusText;
    throw new Error(err);
  }
  return data || {};
}
function $(id) { return document.getElementById(id); }
function opt(text, val) { const o = document.createElement("option"); o.textContent = text; o.value = val; return o; }
function msg(e) { try { return JSON.stringify(e); } catch { return String(e); } }

// ---------- state ----------
let currentSid = null;
let logsPollTimer = null;
let qrWin = null;           // ★ 새 창 핸들
const EXCUSES_PAGE_SIZE = 10;
let excusesData = [];
let excusesPage = 0;

// ---------- entry ----------
window.addEventListener("DOMContentLoaded", async () => {
  $("btnStart").addEventListener("click", onStartSession);
  $("btnManual").addEventListener("click", onManual);
  $("btnManualExcuse").addEventListener("click", onManualExcuse);
  $("btnDelete").addEventListener("click", onDeleteSession);
  $("btnGmail").addEventListener("click", onGmail);
  $("btnCSV").addEventListener("click", onCSV);
  $("btnCSVExcuse").addEventListener("click", onCSVExcuse);
  $("btnCSVAll").addEventListener("click", onCSVAll);
  $("btnAnalyze").addEventListener("click", onAnalyze);

  $("sessionSel").addEventListener("change", async () => {
    currentSid = parseInt($("sessionSel").value, 10);
    stopLogsPolling();
    setSessionButtons();
    await refreshAll();
  });

  await loadSessions();
  await refreshAll();
});

// ---------- sessions ----------
async function loadSessions() {
  const data = await getJSON("/api/sessions");
  const sel = $("sessionSel");
  sel.innerHTML = "";
  (data.sessions || []).forEach(s => {
    sel.appendChild(opt(`#${s.id} : ${s.start_time} ~ ${s.end_time}`, s.id));
  });
  if (sel.options.length) { sel.selectedIndex = 0; currentSid = parseInt(sel.value, 10); }
  else currentSid = null;
  setSessionButtons();
}

function setSessionButtons() {
  const hasSession = Number.isInteger(currentSid) && currentSid > 0;
  const manualBtn = $("btnManual");
  const manualExcuseBtn = $("btnManualExcuse");
  const deleteBtn = $("btnDelete");
  if (manualBtn) {
    manualBtn.style.display = hasSession ? "inline-block" : "none";
    manualBtn.disabled = !hasSession;
  }
  if (manualExcuseBtn) {
    manualExcuseBtn.style.display = hasSession ? "inline-block" : "none";
    manualExcuseBtn.disabled = !hasSession;
  }
  if (deleteBtn) {
    deleteBtn.style.display = hasSession ? "inline-block" : "none";
    deleteBtn.disabled = !hasSession;
  }
}

// ---------- tables ----------
async function refreshAll() {
  if (!currentSid) {
    $("hint").textContent = "세션을 시작해 주세요.";
    clearTable("logsTbl");
    clearTable("excuseTbl");
    clearTable("susTbl");
    setSessionButtons();
    return;
  }
  $("hint").textContent = `세션 선택 (#${currentSid})`;
  setSessionButtons();

  try { await refreshExcusesForSession(currentSid); } catch (e) { console.warn(e); }
  await refreshRecentLogs();
  startLogsPolling();
}

function clearTable(id) { $(id).querySelector("tbody").innerHTML = ""; }

// 공결 목록 (현재 세션 기준, 없으면 최근 기록)
async function refreshExcusesForSession(sessionId) {
  let list = [];
  let sessionDate = "";

  if (Number.isInteger(sessionId) && sessionId > 0) {
    try {
      const data = await getJSON(`/api/excuses/session/${sessionId}`);
      sessionDate = data.session_date || "";
      if (Array.isArray(data.excuses)) {
        list = data.excuses.map(item => ({ ...item, session_date: item.session_date || sessionDate }));
      }
    } catch (err) {
      console.warn(err);
    }
  }

  if (!list.length) {
    try {
      const fallback = await getJSON(`/api/excuses/recent?days=365&limit=200`);
      list = (fallback.rows || []).map(item => ({ ...item, session_date: item.session_date || "" }));
    } catch (err) {
      console.warn(err);
    }
  }

  excusesData = list;
  excusesPage = 0;
  renderExcuses();
}

function renderExcuses() {
  const tb = $("excuseTbl").querySelector("tbody");
  const pager = $("excusePager");
  tb.innerHTML = "";

  if (!Array.isArray(excusesData) || !excusesData.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="6">표시할 공결 내역이 없습니다.</td>';
    tb.appendChild(tr);
    if (pager) pager.innerHTML = "";
    return;
  }

  const pageCount = Math.ceil(excusesData.length / EXCUSES_PAGE_SIZE);
  if (excusesPage >= pageCount) excusesPage = pageCount - 1;
  if (excusesPage < 0) excusesPage = 0;

  const start = excusesPage * EXCUSES_PAGE_SIZE;
  const slice = excusesData.slice(start, start + EXCUSES_PAGE_SIZE);

  slice.forEach(r => {
    const tr = document.createElement("tr");
    const manage = r.id ? `<button type="button" class="btn warn" style="padding:4px 8px;font-size:0.8rem" onclick="onDeleteExcuse(${r.id})">삭제</button>` : "";
    tr.innerHTML = `<td>${r.session_date || ""}</td>
                    <td>${r.student_id}</td>
                    <td>${r.excuse_type}</td>
                    <td>${r.evidence_ok ? "O" : "X"}</td>
                    <td>${r.notes || ""}</td>
                    <td>${manage}</td>`;
    tb.appendChild(tr);
  });

  if (pager) {
    const prevDisabled = excusesPage <= 0 ? "disabled" : "";
    const nextDisabled = excusesPage >= pageCount - 1 ? "disabled" : "";
    pager.innerHTML = `
      <button class="btn" style="padding:4px 10px;font-size:0.8rem" ${prevDisabled} onclick="changeExcusePage(-1)">이전</button>
      <span>페이지 ${excusesPage + 1} / ${pageCount}</span>
      <button class="btn" style="padding:4px 10px;font-size:0.8rem" ${nextDisabled} onclick="changeExcusePage(1)">다음</button>
    `;
  }
}

function changeExcusePage(delta) {
  excusesPage += delta;
  renderExcuses();
}

// 최근 5명만 표시(최신이 위)
async function refreshRecentLogs() {
  if (!currentSid) return;
  try {
    const d = await getJSON(`/api/attendance/session/${currentSid}/list`);
    const all = (d.logs || []);
    const recent = all.slice(-5).reverse();
    const tb = $("logsTbl").querySelector("tbody");
    tb.innerHTML = "";
    recent.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${r.student_id}</td>
                      <td>${r.checked_at}</td>
                      <td>${r.device_name || ""}</td>
                      <td>${r.ip || ""}</td>
                      <td>${r.note || ""}</td>
                      <td><button type="button" class="btn warn" style="padding:4px 8px;font-size:0.8rem" onclick="onDeleteLog(${r.log_id})">삭제</button></td>`;
      tb.appendChild(tr);
    });
  } catch (e) { console.warn(e); }
}

function startLogsPolling() {
  stopLogsPolling();
  logsPollTimer = setInterval(refreshRecentLogs, 3000);
}
function stopLogsPolling() {
  if (logsPollTimer) { clearInterval(logsPollTimer); logsPollTimer = null; }
}

async function openQrBoardWindow(sessionId) {
  if (!sessionId) return;
  try {
    const info = await getJSON(`/api/qr/current?session_id=${sessionId}`);
    const fallbackOrigin = window.location.origin;

    let boardUrl = null;
    if (info.qrboard_url) {
      try {
        boardUrl = new URL(info.qrboard_url).toString();
      } catch (_) {
        boardUrl = info.qrboard_url;
      }
    }
    if (!boardUrl && info.qrboard_path) {
      try {
        boardUrl = new URL(info.qrboard_path, fallbackOrigin).toString();
      } catch (_) {
        boardUrl = `${fallbackOrigin}${info.qrboard_path}`;
      }
    }
    if (!boardUrl) {
      const candidateBase = info.public_base_url || "";
      try {
        if (candidateBase) {
          boardUrl = new URL(`/qrboard?session_id=${sessionId}`, candidateBase).toString();
        }
      } catch (_) {
        boardUrl = null;
      }
    }
    if (!boardUrl) {
      boardUrl = `${fallbackOrigin}/qrboard?session_id=${sessionId}`;
    }

    const feat = "width=480,height=640,noopener=yes,noreferrer=yes";
    if (qrWin && !qrWin.closed) {
      try { qrWin.location.href = boardUrl; }
      catch { qrWin.close(); qrWin = window.open(boardUrl, "_blank", feat); }
    } else {
      qrWin = window.open(boardUrl, "_blank", feat);
    }
    if (!qrWin) {
      throw new Error("팝업이 차단되었습니다. 팝업 허용 후 다시 시도하세요.");
    }
  } catch (e) {
    alert("QR 보드를 열 수 없습니다: " + msg(e));
  }
}

// ---------- actions ----------
async function onStartSession() {
  try {
    const res = await postJSON("/api/session/start", { hours: 2 });
    await loadSessions();
    [...$("sessionSel").options].forEach((o, i) => {
      if (parseInt(o.value, 10) === res.session_id) $("sessionSel").selectedIndex = i;
    });
    currentSid = res.session_id;
    $("hint").textContent = `세션 시작 (#${currentSid})`;
    setSessionButtons();
    await refreshAll();

    await openQrBoardWindow(currentSid);
  } catch (e) { alert(msg(e)); }
}

async function onManual() {
  if (!currentSid) return alert("세션을 선택하세요.");
  const studentId = prompt("학번을 입력해주세요:");
  if (!studentId) return;
  const note = prompt("비고(예: 임의 출석)", "임의 출석") || "임의 출석";
  try {
    await postJSON("/api/attendance/manual", { session_id: currentSid, student_id: studentId.trim(), note: note.trim() });
    await refreshRecentLogs();
    alert("임의 출석이 기록되었습니다.");
  } catch (e) {
    alert(msg(e));
  }
}

async function onManualExcuse() {
  if (!currentSid) return alert("세션을 선택하세요.");
  const studentId = prompt("학번을 입력해주세요:");
  if (!studentId) return;
  const type = (prompt("사유 유형을 입력하세요 (공결/병결)", "공결") || "공결").trim();
  if (!["공결", "병결"].includes(type)) {
    alert("사유 유형은 공결 또는 병결만 가능합니다.");
    return;
  }
  const evidenceOk = confirm("증빙 자료가 있습니까?");
  const note = prompt("비고", "");
  try {
    await postJSON("/api/excuses/manual", {
      session_id: currentSid,
      student_id: studentId.trim(),
      excuse_type: type,
      evidence_ok: evidenceOk,
      notes: note ? note.trim() : "",
    });
    await refreshExcusesForSession(currentSid);
    alert("공결 내역이 기록되었습니다.");
  } catch (e) {
    alert(msg(e));
  }
}

async function onDeleteLog(logId) {
  if (!logId) return;
  const ok = confirm("해당 출석 기록을 삭제하시겠습니까?");
  if (!ok) return;
  try {
    await deleteJSON(`/api/attendance/log/${logId}`);
    await refreshRecentLogs();
    alert("출석 기록이 삭제되었습니다.");
  } catch (e) {
    alert(msg(e));
  }
}

async function onDeleteExcuse(excuseId) {
  if (!excuseId) return;
  const ok = confirm("해당 공결 기록을 삭제하시겠습니까?");
  if (!ok) return;
  try {
    await deleteJSON(`/api/excuses/${excuseId}`);
    await refreshExcusesForSession(currentSid);
    alert("공결 기록이 삭제되었습니다.");
  } catch (e) {
    alert(msg(e));
  }
}

window.changeExcusePage = changeExcusePage;



async function onDeleteSession() {
  if (!currentSid) return alert("세션을 선택하세요.");
  const ok = confirm(`세션 #${currentSid}을 삭제하면 출석 기록이 모두 사라집니다.\n삭제하시겠습니까?`);
  if (!ok) return;
  try {
    await deleteJSON(`/api/session/${currentSid}`);
    if (qrWin && !qrWin.closed) { try { qrWin.close(); } catch(_){} }
    qrWin = null;
    await loadSessions();
    await refreshAll();
    setSessionButtons();
    alert("세션이 삭제되었습니다.");
  } catch (e) {
    alert(msg(e));
  }
}

async function onGmail() {
  try {
    $("btnGmail").disabled = true;
    const res = await postJSON(`/api/excuses/gmail/ingest?days=30&query=${encodeURIComponent("")}`, {});
    await refreshExcusesForSession(currentSid);
    const d = await getJSON(`/api/excuses/recent?days=365&limit=50`);
    const cnt = (d.rows || []).length;
    const sidMissing = res.sid_missing ?? 0;
    const invalid = res.invalid_sid ?? 0;
    const skipped = res.skipped ?? 0;
    const failed = res.failed ?? 0;
    const geminiStatus = res.gemini_active ? "Gemini 분석 실행" : "Gemini 미사용 (휴리스틱)";
    alert(
      `Gmail 처리 완료\nfound: ${res.found}\nupserted: ${res.upserted}\nsid_missing: ${sidMissing}` +
      `\ninvalid_sid: ${invalid}\nskipped: ${skipped}\nfailed: ${failed}\n${geminiStatus}` +
      `\n\n최근 공결 표시 건수: ${cnt}건`
    );
  } catch (e) { alert(msg(e)); }
  finally { $("btnGmail").disabled = false; }
}

function onCSV() {
  if (!currentSid) return alert("세션을 선택하세요.");
  window.open(`/api/export/session/${currentSid}/attendance.csv`, "_blank");
}
function onCSVExcuse() {
  window.open(`/api/export/excuses/recent.csv?days=365`, "_blank");
}
function onCSVAll() {
  window.open(`/api/export/attendance/overall.csv`, "_blank");
}

async function onAnalyze() {
  if (!currentSid) return alert("세션을 선택하세요.");
  try {
    const res = await getJSON(`/api/anomaly/session/${currentSid}`);
    const tb = $("susTbl").querySelector("tbody");
    tb.innerHTML = "";
    const suspects = (res.results || []).filter(r => (r.flags || []).length);
    if (!suspects.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="2">이상 징후가 발견되지 않았습니다.</td>';
      tb.appendChild(tr);
    } else {
      suspects.sort((a,b) => a.score - b.score);
      suspects.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${r.student_id}</td><td>${r.flags.join(", ")}</td>`;
        tb.appendChild(tr);
      });
    }
    alert("분석 결과가 갱신되었습니다.");
  } catch (e) { alert(msg(e)); }
}
