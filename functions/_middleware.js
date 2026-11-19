// 구글 로그인으로 사이트 전체를 보호하는 Cloudflare Pages 미들웨어.
//
// 필요한 환경 변수 (Cloudflare Pages 프로젝트 설정):
//   GOOGLE_CLIENT_ID  Google OAuth 클라이언트 ID (일반 변수)
//   ALLOWED_EMAILS    접속 허용 구글 이메일, 쉼표로 구분 (비밀값)
//   SESSION_SECRET    세션 쿠키 서명용 임의 문자열, 32자 이상 (비밀값)
// 하나라도 없으면 모든 요청을 막는다 (fail closed).
//
// 인증 등록관리:
//   ALLOWED_EMAILS 에 있는 계정은 관리자다. 항상 접속할 수 있고 /admin 에서 신청을 승인한다.
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
// 키: user:<email>  값/메타데이터: { email, name, status, requestedAt, decidedAt, decidedBy }
// status: pending(승인 대기) | approved(승인) | rejected(거절)
const USER_PREFIX = 'user:';
const STATUSES = ['pending', 'approved', 'rejected'];

function isAdmin(env, email) {
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

async function canAccess(env, email) {
  if (!email) return false;
  if (isAdmin(env, email)) return true;
  const rec = await getRecord(env, email);
  return !!rec && rec.status === 'approved';
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
<title>인증 등록관리</title>
<style>
  :root {
    --bg:#f3f5f8; --card:#fff; --text:#1f2933; --muted:#5f6b7a; --line:#e2e6eb; --err:#b42318;
    --bar:#2f6fdb; --ok:#3d8b5f; --ok-bg:#e9f5ee; --warn:#c4320a; --warn-bg:#fdeee8;
    --watch-text:#8a5f00; --watch-bg:#fdf6e0; --head:#17324d; --head-text:#fff;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#12151a; --card:#1c2027; --text:#e4e7eb; --muted:#9aa5b1; --line:#313742; --err:#f97066;
      --bar:#5b8ff0; --ok:#5cb784; --ok-bg:#1f3329; --warn:#f38744; --warn-bg:#3a2620;
      --watch-text:#f2c94c; --watch-bg:#3a331d; --head:#0d1a28; --head-text:#e4e7eb;
    }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); line-height:1.5; font-size:15px;
    font-family:"Malgun Gothic","Apple SD Gothic Neo","Noto Sans KR",sans-serif; }
  .topbar { background:var(--head); color:var(--head-text); display:flex; align-items:center;
    justify-content:space-between; gap:16px; flex-wrap:wrap; padding:14px 32px; }
  .topbar h1 { font-size:1.35rem; margin:0; }
  .topbar .sub { margin:2px 0 0; font-size:.88rem; opacity:.8; }
  .topbar .meta { display:flex; gap:16px; align-items:center; font-size:.88rem; }
  .topbar a { color:inherit; }
  main { max-width:1100px; margin:0 auto; padding:20px 32px 32px; }
  .tabs { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
  .tabs button { border:1px solid var(--line); background:var(--card); color:var(--text);
    border-radius:999px; padding:6px 14px; font:inherit; cursor:pointer; }
  .tabs button[aria-selected="true"] { background:var(--bar); border-color:var(--bar); color:#fff; font-weight:600; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--line); white-space:nowrap; }
  th { color:var(--muted); font-size:.85rem; font-weight:600; }
  tr:last-child td { border-bottom:0; }
  td.email { font-weight:600; }
  td.when { color:var(--muted); font-size:.88rem; }
  .actions { display:flex; gap:6px; justify-content:flex-end; }
  .actions button { border:1px solid var(--line); background:var(--card); color:var(--text);
    border-radius:6px; padding:4px 12px; font:inherit; font-size:.88rem; cursor:pointer; }
  .actions .approve { background:var(--ok); border-color:var(--ok); color:#fff; font-weight:600; }
  .actions .reject { color:var(--warn); }
  .actions button:disabled { opacity:.5; cursor:wait; }
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
    <h1>인증 등록관리</h1>
    <p class="sub">새로 로그인한 구글 계정의 접속을 승인하거나 거절합니다.</p>
  </div>
  <div class="meta">
    <span>${escapeHtml(email)}</span>
    <a href="/">대시보드</a>
    <a href="/logout">로그아웃</a>
  </div>
</header>
<main>
  <div class="tabs" role="tablist">
    <button role="tab" data-tab="pending" aria-selected="true">승인 대기<span class="badge" id="cnt-pending">0</span></button>
    <button role="tab" data-tab="approved" aria-selected="false">승인됨 <span id="cnt-approved">0</span></button>
    <button role="tab" data-tab="rejected" aria-selected="false">거절됨 <span id="cnt-rejected">0</span></button>
  </div>
  <p id="msg" role="status">불러오는 중…</p>
  <div class="card">
    <table>
      <thead><tr><th>구글 계정</th><th>이름</th><th>신청 시각</th><th>처리</th><th></th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <p class="note">관리자(설정값 ALLOWED_EMAILS에 있는 계정)는 목록에 없어도 항상 접속할 수 있습니다.
    승인을 취소하면 늦어도 1분 안에 그 계정의 접속이 막힙니다.</p>
</main>
<script>
  var users = [], tab = 'pending';
  var ACTIONS = {
    pending: [['approve', '승인'], ['reject', '거절']],
    approved: [['reject', '승인 취소']],
    rejected: [['approve', '승인'], ['delete', '기록 삭제']]
  };
  var msg = document.getElementById('msg');
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
  function render() {
    ['pending', 'approved', 'rejected'].forEach(function (s) {
      document.getElementById('cnt-' + s).textContent = users.filter(function (u) { return u.status === s; }).length;
    });
    document.querySelectorAll('.tabs button').forEach(function (b) {
      b.setAttribute('aria-selected', String(b.dataset.tab === tab));
    });
    var rows = document.getElementById('rows');
    rows.textContent = '';
    var list = users.filter(function (u) { return u.status === tab; });
    if (!list.length) {
      var tr = document.createElement('tr');
      var td = cell(tr, tab === 'pending' ? '승인을 기다리는 신청이 없습니다.' : '해당하는 계정이 없습니다.', 'empty');
      td.colSpan = 5;
      rows.appendChild(tr);
      return;
    }
    list.forEach(function (u) {
      var tr = document.createElement('tr');
      cell(tr, u.email, 'email');
      cell(tr, u.name || '-');
      cell(tr, fmt(u.requestedAt), 'when');
      cell(tr, u.decidedAt ? fmt(u.decidedAt) + ' · ' + (u.decidedBy || '') : '-', 'when');
      var td = cell(tr, '');
      var box = document.createElement('div');
      box.className = 'actions';
      ACTIONS[tab].forEach(function (a) {
        var b = document.createElement('button');
        b.className = a[0];
        b.textContent = a[1];
        b.onclick = function () { act(u.email, a[0], a[1], b); };
        box.appendChild(b);
      });
      td.appendChild(box);
      rows.appendChild(tr);
    });
  }
  function load() {
    return fetch('/api/access', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status)); return j; }); })
      .then(function (j) { users = j.users || []; msg.className = ''; msg.textContent = ''; render(); })
      .catch(function (e) { msg.className = 'error'; msg.textContent = '목록을 불러오지 못했습니다: ' + e.message; });
  }
  function act(email, action, label, btn) {
    if ((action === 'reject' || action === 'delete') && !confirm(email + ' 계정을 ' + label + '할까요?')) return;
    btn.disabled = true;
    fetch('/api/access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, action: action })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
        if (action === 'delete') users = users.filter(function (u) { return u.email !== email; });
        else users = users.map(function (u) { return u.email === email ? j.user : u; });
        msg.className = '';
        msg.textContent = email + ' · ' + label + ' 완료';
        render();
      });
    }).catch(function (e) {
      btn.disabled = false;
      msg.className = 'error';
      msg.textContent = label + ' 실패: ' + e.message;
    });
  }
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
    if (!isAdmin(env, email)) {
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
    const admin = isAdmin(env, email);
    let pending = 0;
    if (admin && env.ACCESS) pending = (await listRecords(env)).filter((r) => r.status === 'pending').length;
    return json({ email, admin, pending }, 200);
  }

  if (path === '/admin' || path === '/api/access') {
    if (!isAdmin(env, email)) {
      return path === '/admin'
        ? html(page('권한 없음', '<h1>관리자만 볼 수 있습니다</h1><p><a href="/">대시보드로 돌아가기</a></p>'), 403)
        : json({ error: '관리자만 사용할 수 있습니다.' }, 403);
    }
    if (path === '/admin') return html(adminPage(email));
    if (!env.ACCESS) return json({ error: 'ACCESS 저장소(KV) 바인딩이 없습니다.' }, 503);

    if (request.method === 'GET') {
      const list = await listRecords(env);
      list.sort((a, b) => String(b.requestedAt || '').localeCompare(String(a.requestedAt || '')));
      return json({ users: list }, 200);
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
    const rec = await getRecord(env, target);
    if (!rec) return json({ error: '해당 신청을 찾지 못했습니다.' }, 404);
    if (action === 'delete') {
      await env.ACCESS.delete(USER_PREFIX + target);
      return json({ ok: true }, 200);
    }
    const status = { approve: 'approved', reject: 'rejected', reset: 'pending' }[action];
    if (!STATUSES.includes(status)) return json({ error: '알 수 없는 작업입니다.' }, 400);
    const updated = { ...rec, status, decidedAt: new Date().toISOString(), decidedBy: email };
    await putRecord(env, updated);
    return json({ ok: true, user: updated }, 200);
  }

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'private, no-cache');
  return out;
}
