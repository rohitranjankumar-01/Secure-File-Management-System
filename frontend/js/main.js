// main.js — Shared utilities used on every page

// ── Auth ─────────────────────────────────────────────────────────────────────
async function logout() {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = 'login.html';
}

// ── Messages ──────────────────────────────────────────────────────────────────
function showMsg(el, text, type) {
  // type = 'ok' or 'err'
  if (!el) return;
  el.textContent = text;
  el.className   = 'msg ' + (type === 'ok' ? 'ok' : 'err');
}

// ── Password visibility toggle ────────────────────────────────────────────────
function togglePw(id) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
}

// ── File icon ─────────────────────────────────────────────────────────────────
function fileIcon(t) {
  if (!t) return '📄';
  t = t.toLowerCase();
  if (t.includes('pdf'))                      return '📕';
  if (t.includes('image'))                    return '🖼️';
  if (t.includes('video'))                    return '🎬';
  if (t.includes('audio'))                    return '🎵';
  if (t.includes('zip') || t.includes('compress')) return '📦';
  if (t.includes('sheet') || t.includes('excel') || t.includes('csv')) return '📊';
  if (t.includes('word') || t.includes('doc')) return '📝';
  if (t.includes('presentation') || t.includes('ppt')) return '📊';
  return '📄';
}

// ── Password strength bar ─────────────────────────────────────────────────────
function pwStrength(pw) {
  let s = 0;
  if (pw.length >= 8)                             s++;
  if (/[A-Z]/.test(pw))                           s++;
  if (/\d/.test(pw))                              s++;
  if (/[!@#$%^&*()\-_=+\[\]{};:'",.<>?]/.test(pw)) s++;
  const labels = ['','Weak','Fair','Good','Strong'];
  return s === 0 ? '' :
    `<div class="pw-bar"><div class="pw-fill s${s}" style="width:${s*25}%"></div></div>
     <small class="pw-lbl s${s}">${labels[s]}</small>`;
}

// ── Format bytes ──────────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (b < 1024)    return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}

// ── Delay helper ──────────────────────────────────────────────────────────────
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
