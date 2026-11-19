// 구글 로그인으로 사이트 전체를 보호하는 Cloudflare Pages 미들웨어.
//
// 필요한 환경 변수 (Cloudflare Pages 프로젝트 설정):
//   GOOGLE_CLIENT_ID  Google OAuth 클라이언트 ID (일반 변수)
//   ALLOWED_EMAILS    접속 허용 구글 이메일, 쉼표로 구분 (비밀값)
//   SESSION_SECRET    세션 쿠키 서명용 임의 문자열, 32자 이상 (비밀값)
// 하나라도 없으면 모든 요청을 막는다 (fail closed).
//
// 접속 권한 관리 (대시보드의 '관리' 버튼 → /admin):
//   ALLOWED_EMAILS 에 있는 계정은 기본 관리자다. 항상 접속할 수 있고 화면에서 바꿀 수 없다.
//   관리자는 이메일로 열람자/관리자 권한을 바로 부여하거나, 신청을 승인·거절·해제할 수 있다.
//   그 밖의 구글 계정이 로그인하면 KV(바인딩 ACCESS, wrangler.toml)에 '승인 대기'로 기록되고,
//   관리자가 승인한 뒤부터 접속할 수 있다. ACCESS 바인딩이 없으면 관리자만 접속된다.

const COOKIE = 'crms_session';
const SESSION_HOURS = 12;
const GOOGLE_CERTS = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64url(buf) {
  let s = '';
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function allowedEmails(env) {
  return new Set(
    String(env.ALLOWED_EMAILS || '')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean)
  );
}

// ---- 인증 등록 기록 (KV) ----
// 키: user:<email>  값/메타데이터: { email, name, status, role, requestedAt, decidedAt, decidedBy }
// role: viewer(열람자, 기본) | admin(관리자: 권한 관리 가능)
// status: pending(승인 대기) | approved(승인) | rejected(거절)
const USER_PREFIX = 'user:';
const STATUSES = ['pending', 'approved', 'rejected'];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// 기본 관리자: 설정값 ALLOWED_EMAILS. 항상 접속되고 화면에서 바꿀 수 없다.
function isOwner(env, email) {
  return !!email && allowedEmails(env).has(email);
}

async function getRecord(env, email) {
  if (!env.ACCESS || !email) return null;
  return env.ACCESS.get(USER_PREFIX + email, { type: 'json' });
}

async function putRecord(env, rec) {
  // 목록 조회 때 값을 따로 읽지 않도록 메타데이터에도 같이 넣는다 (1KB 이내)
  const meta = { ...rec, name: String(rec.name || '').slice(0, 100) };
  await env.ACCESS.put(USER_PREFIX + rec.email, JSON.stringify(rec), { metadata: meta });
}

async function listRecords(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.ACCESS.list({ prefix: USER_PREFIX, cursor });
    for (const k of page.keys) {
      out.push(k.metadata || { email: k.name.slice(USER_PREFIX.length), status: 'pending' });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

// 접속 권한: owner(기본 관리자) | admin(관리자) | viewer(열람자) | null(권한 없음)
async function roleOf(env, email) {
  if (!email) return null;
  if (isOwner(env, email)) return 'owner';
  const rec = await getRecord(env, email);
  if (!rec || rec.status !== 'approved') return null;
  return rec.role === 'admin' ? 'admin' : 'viewer';
}

async function canAccess(env, email) {
  return (await roleOf(env, email)) !== null;
}

async function isManager(env, email) {
  const r = await roleOf(env, email);
  return r === 'owner' || r === 'admin';
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function safeNext(value) {
  // 같은 사이트 안의 경로만 허용 (외부로 튕기는 open redirect 방지)
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !value.startsWith('/\\')
    ? value
    : '/';
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function makeSession(email, secret) {
  const payload = bytesToB64url(
    enc.encode(JSON.stringify({ email, exp: Math.floor(Date.now() / 1000) + SESSION_HOURS * 3600 }))
  );
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(payload));
  return payload + '.' + bytesToB64url(sig);
}

async function readSession(value, secret) {
  if (!value) return null;
  const [payload, sig] = value.split('.');
  if (!payload || !sig) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64urlToBytes(sig), enc.encode(payload));
    if (!ok) return null;
    const data = JSON.parse(dec.decode(b64urlToBytes(payload)));
    if (typeof data.email !== 'string' || !(data.exp > Date.now() / 1000)) return null;
    return data.email;
  } catch {
    return null;
  }
}

async function verifyGoogleIdToken(token, clientId) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('토큰 형식 오류');
  const header = JSON.parse(dec.decode(b64urlToBytes(parts[0])));
  if (header.alg !== 'RS256') throw new Error('지원하지 않는 서명 방식');

  const res = await fetch(GOOGLE_CERTS, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!res.ok) throw new Error('구글 공개키를 받지 못함');
  const { keys } = await res.json();
  const jwk = (keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('알 수 없는 서명 키');

  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    b64urlToBytes(parts[2]),
    enc.encode(parts[0] + '.' + parts[1])
  );
  if (!valid) throw new Error('서명 검증 실패');

  const claims = JSON.parse(dec.decode(b64urlToBytes(parts[1])));
  const now = Date.now() / 1000;
  if (!GOOGLE_ISSUERS.includes(claims.iss)) throw new Error('발급자 불일치');
  if (claims.aud !== clientId) throw new Error('클라이언트 ID 불일치');
  if (!(claims.exp > now)) throw new Error('토큰 만료');
  if (claims.email_verified !== true && claims.email_verified !== 'true') throw new Error('이메일 미인증 계정');
  return { email: String(claims.email || '').toLowerCase(), name: String(claims.name || '') };
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function html(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function page(title, inner) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --text:#1f2933; --muted:#616e7c; --line:#e4e7eb; --err:#b42318; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171c; --card:#1d2128; --text:#e4e7eb; --muted:#9aa5b1; --line:#323843; --err:#f97066; }
  }
  body { margin:0; background:var(--bg); color:var(--text); line-height:1.5;
    font-family:"Malgun Gothic","Apple SD Gothic Neo","Noto Sans KR",sans-serif; }
  main { max-width:420px; margin:12vh auto 0; padding:0 16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:28px 24px; text-align:center; }
  h1 { font-size:1.2rem; margin:0 0 6px; }
  p { color:var(--muted); margin:0 0 20px; font-size:.92rem; }
  #gbtn { display:flex; justify-content:center; min-height:44px; }
  #msg { color:var(--err); margin:16px 0 0; font-size:.9rem; }
  #msg.info { color:var(--text); background:var(--bg); border-radius:8px; padding:10px 12px; }
  a { color:inherit; }
</style>
</head>
<body><main><div class="card">${inner}</div></main></body>
</html>`;
}

function loginPage(clientId, next) {
  const nextJs = JSON.stringify(next).replace(/</g, '\\u003c');
  return page(
    '로그인 · 공종별 현장평가',
    `<h1>공종별 현장평가 조회</h1>
<p>허용된 구글 계정으로 로그인해 주세요.</p>
<div id="gbtn"></div>
<div id="msg" role="alert"></div>
<script src="https://accounts.google.com/gsi/client" async onload="initGoogle()"></script>
<script>
  var NEXT = ${nextJs};
  function initGoogle() {
    google.accounts.id.initialize({ client_id: ${JSON.stringify(clientId)}, callback: onCredential });
    google.accounts.id.renderButton(document.getElementById('gbtn'),
      { theme: 'outline', size: 'large', text: 'signin_with', locale: 'ko' });
  }
  function onCredential(r) {
    var msg = document.getElementById('msg');
    msg.textContent = '';
    fetch('/auth/google', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: r.credential })
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (j) {
        if (res.ok) { location.replace(NEXT); return; }
        msg.className = j.pending ? 'info' : '';
        msg.textContent = j.error || ('로그인 실패 (HTTP ' + res.status + ')');
        google.accounts.id.disableAutoSelect();
      });
    }).catch(function () { msg.textContent = '네트워크 오류로 로그인하지 못했습니다.'; });
  }
</script>`
  );
}

function adminPage(email) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>관리 · 접속 권한</title>
<style>
  :root {
    --bg:#f3f5f8; --card:#fff; --text:#1f2933; --muted:#5f6b7a; --line:#e2e6eb; --err:#b42318;
    --bar:#2f6fdb; --bar-bg:#e8eefb; --ok:#3d8b5f; --ok-bg:#e9f5ee; --warn:#c4320a; --warn-bg:#fdeee8;
    --head:#17324d; --head-text:#fff;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#12151a; --card:#1c2027; --text:#e4e7eb; --muted:#9aa5b1; --line:#313742; --err:#f97066;
      --bar:#5b8ff0; --bar-bg:#26304a; --ok:#5cb784; --ok-bg:#1f3329; --warn:#f38744; --warn-bg:#3a2620;
      --head:#0d1a28; --head-text:#e4e7eb;
    }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); line-height:1.5; font-size:15px;
    font-family:"Malgun Gothic","Apple SD Gothic Neo","Noto Sans KR",sans-serif; }
  .topbar { background:var(--head); color:var(--head-text); display:flex; align-items:center;
    justify-content:space-between; gap:16px; flex-wrap:wrap; padding:14px 32px; }
  .topbar h1 { font-size:1.35rem; margin:0; }
  .topbar .sub { margin:2px 0 0; font-size:.88rem; opacity:.8; }
  .topbar .meta { display:flex; gap:16px; align-items:center; font-size:.88rem; flex-wrap:wrap; }
  .topbar a { color:inherit; }
  main { max-width:1100px; margin:0 auto; padding:20px 32px 32px; }
  h2 { font-size:1.05rem; margin:0 0 4px; }
  .hint { color:var(--muted); font-size:.85rem; margin:0 0 12px; }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 18px; margin-bottom:20px; }
  form.grant { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  form.grant input, form.grant select { font:inherit; padding:7px 10px; border:1px solid var(--line);
    border-radius:6px; background:var(--bg); color:var(--text); }
  form.grant input { flex:1 1 260px; min-width:0; }
  button { font:inherit; cursor:pointer; }
  .primary { background:var(--bar); border:1px solid var(--bar); color:#fff; border-radius:6px; padding:7px 16px; font-weight:600; }
  .tabs { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
  .tabs button { border:1px solid var(--line); background:var(--card); color:var(--text); border-radius:999px; padding:6px 14px; }
  .tabs button[aria-selected="true"] { background:var(--bar); border-color:var(--bar); color:#fff; font-weight:600; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--line); white-space:nowrap; }
  th { color:var(--muted); font-size:.85rem; font-weight:600; }
  tr:last-child td { border-bottom:0; }
  td.email { font-weight:600; }
  td.when { color:var(--muted); font-size:.88rem; }
  .role { display:inline-block; border-radius:999px; padding:1px 10px; font-size:.82rem; font-weight:600; }
  .role.owner { background:var(--head); color:var(--head-text); }
  .role.admin { background:var(--bar-bg); color:var(--bar); }
  .role.viewer { background:var(--ok-bg); color:var(--ok); }
  .actions { display:flex; gap:6px; justify-content:flex-end; }
  .actions button { border:1px solid var(--line); background:var(--card); color:var(--text); border-radius:6px; padding:4px 12px; font-size:.88rem; }
  .actions .approve { background:var(--ok); border-color:var(--ok); color:#fff; font-weight:600; }
  .actions .reject, .actions .delete { color:var(--warn); }
  .actions .fixed { color:var(--muted); font-size:.85rem; }
  button:disabled { opacity:.5; cursor:wait; }
  .badge { display:inline-block; min-width:20px; padding:0 6px; border-radius:999px; font-size:.8rem;
    background:var(--warn-bg); color:var(--warn); text-align:center; margin-left:4px; font-weight:700; }
  .empty { padding:28px; text-align:center; color:var(--muted); }
  #msg { min-height:1.5em; margin:0 0 10px; color:var(--muted); }
  #msg.error { color:var(--err); }
  .note { color:var(--muted); font-size:.85rem; margin-top:12px; }
  @media (max-width:640px) { .topbar, main { padding-left:16px; padding-right:16px; } }
</style>
</head>
<body>
<header class="topbar">
  <div>
    <h1>관리</h1>
    <p class="sub">구글 계정별 접속 권한을 부여하고, 새 신청을 승인합니다.</p>
  </div>
  <div class="meta">
    <span>${escapeHtml(email)}</span>
    <a href="/">대시보드</a>
    <a href="/logout">로그아웃</a>
  </div>
</header>
<main>
  <section class="panel">
    <h2>이메일로 권한 부여</h2>
    <p class="hint">구글 계정 이메일을 넣으면 신청 절차 없이 바로 접속할 수 있습니다. 관리자 권한을 받은 사람은 이 화면도 쓸 수 있습니다.</p>
    <form class="grant" id="grant-form">
      <input type="email" id="grant-email" placeholder="name@gmail.com" required autocomplete="off" aria-label="구글 계정 이메일">
      <select id="grant-role" aria-label="권한">
        <option value="viewer">열람자 (대시보드 보기)</option>
        <option value="admin">관리자 (보기 + 권한 관리)</option>
      </select>
      <button type="submit" class="primary">권한 부여</button>
    </form>
  </section>

  <div class="tabs" role="tablist">
    <button role="tab" data-tab="pending" aria-selected="true">승인 대기<span class="badge" id="cnt-pending">0</span></button>
    <button role="tab" data-tab="approved" aria-selected="false">권한 보유 <span id="cnt-approved">0</span></button>
    <button role="tab" data-tab="rejected" aria-selected="false">거절·해제 <span id="cnt-rejected">0</span></button>
  </div>
  <p id="msg" role="status">불러오는 중…</p>
  <div class="card">
    <table>
      <thead><tr><th>구글 계정</th><th>이름</th><th>권한</th><th>신청·등록</th><th>최근 처리</th><th></th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <p class="note">기본 관리자는 Cloudflare 설정값 ALLOWED_EMAILS에 있는 계정이라 이 화면에서 바꿀 수 없습니다.
    권한 변경은 늦어도 1분 안에 반영됩니다. 본인 계정의 권한은 직접 바꿀 수 없습니다.</p>
</main>
<script>
  var ME = ${JSON.stringify(email).replace(/</g, '\\u003c')};
  var users = [], owners = [], tab = 'pending';
  var ROLE_LABEL = { owner: '기본 관리자', admin: '관리자', viewer: '열람자' };
  var msg = document.getElementById('msg');
  function actionsFor(u) {
    if (u.status === 'pending') return [['approve', '승인', 'viewer', 'approve'], ['approve', '관리자로 승인', 'admin', 'approve'], ['reject', '거절', '', 'reject']];
    if (u.status === 'approved') return [
      u.role === 'admin' ? ['role', '열람자로 변경', 'viewer', ''] : ['role', '관리자로 지정', 'admin', ''],
      ['reject', '권한 해제', '', 'reject']
    ];
    return [['approve', '다시 승인', 'viewer', 'approve'], ['delete', '기록 삭제', '', 'delete']];
  }
  function fmt(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'short' });
  }
  function cell(tr, text, cls) {
    var td = document.createElement('td');
    if (cls) td.className = cls;
    td.textContent = text;
    tr.appendChild(td);
    return td;
  }
  function rowsFor(status) {
    var list = users.filter(function (u) { return u.status === status; });
    if (status === 'approved') list = owners.map(function (e) { return { email: e, status: 'approved', role: 'owner' }; }).concat(list);
    return list;
  }
  function render() {
    ['pending', 'approved', 'rejected'].forEach(function (s) {
      document.getElementById('cnt-' + s).textContent = rowsFor(s).length;
    });
    document.querySelectorAll('.tabs button').forEach(function (b) {
      b.setAttribute('aria-selected', String(b.dataset.tab === tab));
    });
    var rows = document.getElementById('rows');
    rows.textContent = '';
    var list = rowsFor(tab);
    if (!list.length) {
      var tr = document.createElement('tr');
      var td = cell(tr, tab === 'pending' ? '승인을 기다리는 신청이 없습니다.' : '해당하는 계정이 없습니다.', 'empty');
      td.colSpan = 6;
      rows.appendChild(tr);
      return;
    }
    list.forEach(function (u) {
      var tr = document.createElement('tr');
      cell(tr, u.email, 'email');
      cell(tr, u.name || '-');
      var roleTd = cell(tr, '');
      if (u.status === 'approved') {
        var r = u.role === 'owner' || u.role === 'admin' ? u.role : 'viewer';
        var span = document.createElement('span');
        span.className = 'role ' + r;
        span.textContent = ROLE_LABEL[r];
        roleTd.appendChild(span);
      } else roleTd.textContent = '-';
      cell(tr, u.role === 'owner' ? '설정값' : fmt(u.requestedAt), 'when');
      cell(tr, u.decidedAt ? fmt(u.decidedAt) + ' · ' + (u.decidedBy || '') : '-', 'when');
      var td = cell(tr, '');
      var box = document.createElement('div');
      box.className = 'actions';
      if (u.role === 'owner' || u.email === ME) {
        var f = document.createElement('span');
        f.className = 'fixed';
        f.textContent = u.role === 'owner' ? '변경 불가' : '본인 계정';
        box.appendChild(f);
      } else {
        actionsFor(u).forEach(function (a) {
          var b = document.createElement('button');
          b.className = a[3];
          b.textContent = a[1];
          b.onclick = function () { act({ email: u.email, action: a[0], role: a[2] }, a[1], b); };
          box.appendChild(b);
        });
      }
      td.appendChild(box);
      rows.appendChild(tr);
    });
  }
  function load() {
    return fetch('/api/access', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status)); return j; }); })
      .then(function (j) { users = j.users || []; owners = j.owners || []; msg.className = ''; msg.textContent = ''; render(); })
      .catch(function (e) { msg.className = 'error'; msg.textContent = '목록을 불러오지 못했습니다: ' + e.message; });
  }
  function act(body, label, btn) {
    if ((body.action === 'reject' || body.action === 'delete') && !confirm(body.email + ' 계정을 ' + label + '할까요?')) return Promise.resolve(false);
    btn.disabled = true;
    return fetch('/api/access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
        users = users.filter(function (u) { return u.email !== body.email; });
        if (body.action !== 'delete') users.unshift(j.user);
        msg.className = '';
        msg.textContent = body.email + ' · ' + label + ' 완료';
        btn.disabled = false;
        render();
        return true;
      });
    }).catch(function (e) {
      btn.disabled = false;
      msg.className = 'error';
      msg.textContent = label + ' 실패: ' + e.message;
      return false;
    });
  }
  document.getElementById('grant-form').onsubmit = function (ev) {
    ev.preventDefault();
    var input = document.getElementById('grant-email');
    var role = document.getElementById('grant-role').value;
    var btn = ev.target.querySelector('button');
    act({ email: input.value.trim().toLowerCase(), action: 'grant', role: role }, ROLE_LABEL[role] + ' 권한 부여', btn)
      .then(function (ok) { if (ok) { input.value = ''; tab = 'approved'; render(); } });
  };
  document.querySelectorAll('.tabs button').forEach(function (b) {
    b.onclick = function () { tab = b.dataset.tab; render(); };
  });
  load();
</script>
</body>
</html>`;
}

function sessionCookie(value, maxAge) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (!env.GOOGLE_CLIENT_ID || !env.SESSION_SECRET || allowedEmails(env).size === 0) {
    return html(page('설정 필요', '<h1>로그인 설정이 끝나지 않았습니다</h1><p>관리자에게 문의해 주세요.</p>'), 503);
  }

  // 서버 코드와 설정 파일은 정적 파일로 내보내지 않는다
  if (path === '/functions' || path.startsWith('/functions/') || path === '/wrangler.toml') {
    return new Response('Not found', { status: 404 });
  }

  if (path === '/login') {
    return html(loginPage(env.GOOGLE_CLIENT_ID, safeNext(url.searchParams.get('next'))));
  }

  if (path === '/logout') {
    return new Response(null, {
      status: 302,
      headers: { Location: '/login', 'Set-Cookie': sessionCookie('', 0), 'Cache-Control': 'no-store' },
    });
  }

  if (path === '/auth/google') {
    if (request.method !== 'POST') return json({ error: 'POST만 허용됩니다.' }, 405);
    // CSRF 방지: 같은 사이트에서 보낸 JSON 요청만 받는다
    if (request.headers.get('Origin') !== url.origin) return json({ error: '허용되지 않은 요청입니다.' }, 403);
    if (!(request.headers.get('Content-Type') || '').startsWith('application/json')) {
      return json({ error: '잘못된 요청 형식입니다.' }, 415);
    }
    let email, name;
    try {
      const body = await request.json();
      ({ email, name } = await verifyGoogleIdToken(body.credential, env.GOOGLE_CLIENT_ID));
    } catch (e) {
      return json({ error: '구글 로그인 확인 실패: ' + e.message }, 401);
    }
    if (!isOwner(env, email)) {
      if (!env.ACCESS) {
        return json({ error: `${email} 계정은 접속 권한이 없습니다. 관리자에게 요청해 주세요.` }, 403);
      }
      const rec = await getRecord(env, email);
      if (!rec) {
        await putRecord(env, { email, name, status: 'pending', requestedAt: new Date().toISOString() });
        return json({ pending: true, error: `${email} 계정으로 인증 등록을 신청했습니다. 관리자 승인 후 접속할 수 있습니다.` }, 403);
      }
      if (rec.status === 'pending') {
        return json({ pending: true, error: `${email} 계정은 승인 대기 중입니다. 관리자 승인 후 다시 로그인해 주세요.` }, 403);
      }
      if (rec.status !== 'approved') {
        return json({ error: `${email} 계정의 인증 등록이 거절되었습니다. 관리자에게 문의해 주세요.` }, 403);
      }
    }
    const value = await makeSession(email, env.SESSION_SECRET);
    return new Response(JSON.stringify({ ok: true, email }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': sessionCookie(value, SESSION_HOURS * 3600),
      },
    });
  }

  // 그 밖의 모든 경로는 로그인 필요. 승인이 취소된 사람은 다음 요청부터 막힌다 (KV 반영까지 최대 1분).
  const email = await readSession(getCookie(request, COOKIE), env.SESSION_SECRET);
  if (!(await canAccess(env, email))) {
    const accept = request.headers.get('Accept') || '';
    if (request.method === 'GET' && accept.includes('text/html')) {
      return new Response(null, {
        status: 302,
        headers: { Location: '/login?next=' + encodeURIComponent(path + url.search), 'Cache-Control': 'no-store' },
      });
    }
    return json({ error: '로그인이 필요합니다.' }, 401);
  }

  if (path === '/api/me') {
    const admin = await isManager(env, email);
    let pending = 0;
    if (admin && env.ACCESS) pending = (await listRecords(env)).filter((r) => r.status === 'pending').length;
    return json({ email, admin, pending }, 200);
  }

  if (path === '/admin' || path === '/api/access') {
    if (!(await isManager(env, email))) {
      return path === '/admin'
        ? html(page('권한 없음', '<h1>관리자만 볼 수 있습니다</h1><p><a href="/">대시보드로 돌아가기</a></p>'), 403)
        : json({ error: '관리자만 사용할 수 있습니다.' }, 403);
    }
    if (path === '/admin') return html(adminPage(email));
    if (!env.ACCESS) return json({ error: 'ACCESS 저장소(KV) 바인딩이 없습니다.' }, 503);

    if (request.method === 'GET') {
      const owners = allowedEmails(env);
      const list = (await listRecords(env)).filter((r) => !owners.has(r.email));
      list.sort((a, b) => String(b.decidedAt || b.requestedAt || '').localeCompare(String(a.decidedAt || a.requestedAt || '')));
      return json({ users: list, owners: [...owners] }, 200);
    }
    if (request.method !== 'POST') return json({ error: 'GET, POST만 허용됩니다.' }, 405);
    if (request.headers.get('Origin') !== url.origin) return json({ error: '허용되지 않은 요청입니다.' }, 403);
    if (!(request.headers.get('Content-Type') || '').startsWith('application/json')) {
      return json({ error: '잘못된 요청 형식입니다.' }, 415);
    }
    let body;
    try { body = await request.json(); } catch { return json({ error: '잘못된 요청 형식입니다.' }, 400); }
    const target = String(body.email || '').trim().toLowerCase();
    const action = String(body.action || '');
    const role = body.role === 'admin' ? 'admin' : 'viewer';
    if (!EMAIL_RE.test(target)) return json({ error: '이메일 형식이 올바르지 않습니다.' }, 400);
    if (isOwner(env, target)) return json({ error: '기본 관리자(설정값 ALLOWED_EMAILS)는 여기서 바꿀 수 없습니다.' }, 400);
    if (target === email) return json({ error: '본인 계정의 권한은 직접 바꿀 수 없습니다.' }, 400);

    const now = new Date().toISOString();
    const rec = await getRecord(env, target);
    if (action === 'grant') {
      const updated = { email: target, name: (rec && rec.name) || '', requestedAt: (rec && rec.requestedAt) || now,
        status: 'approved', role, decidedAt: now, decidedBy: email };
      await putRecord(env, updated);
      return json({ ok: true, user: updated }, 200);
    }
    if (!rec) return json({ error: '해당 계정 기록을 찾지 못했습니다.' }, 404);
    if (action === 'delete') {
      await env.ACCESS.delete(USER_PREFIX + target);
      return json({ ok: true }, 200);
    }
    let updated;
    if (action === 'approve') updated = { ...rec, status: 'approved', role };
    else if (action === 'reject') updated = { ...rec, status: 'rejected' };
    else if (action === 'role' && rec.status === 'approved') updated = { ...rec, role };
    else return json({ error: '알 수 없는 작업입니다.' }, 400);
    updated = { ...updated, decidedAt: now, decidedBy: email };
    await putRecord(env, updated);
    return json({ ok: true, user: updated }, 200);
  }

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'private, no-cache');
  return out;
}
