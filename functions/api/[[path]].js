// Cloudflare Pages Function: API untuk Dashboard Freight Forwarder
// Binding yang dibutuhkan : DB (D1)
// Secret yang dibutuhkan  : AUTH_SECRET, PASS_SALES, PASS_OPERATION, PASS_PROJECTCONTROL

const USERS = {
  sales:          { role: 'sales', passVar: 'PASS_SALES' },
  operation:      { role: 'ops',   passVar: 'PASS_OPERATION' },
  projectcontrol: { role: 'pc',    passVar: 'PASS_PROJECTCONTROL' },
};
const MODA = ['Air Freight', 'Sea Freight', 'Trucking'];
const TERM = ['Door to Door', 'Door to Port', 'Port to Door', 'Port to Port'];
const MAX_B64 = 1.9 * 1000 * 1000; // batas baris D1 = 2 MB; setara file asli ±1,4 MB
const TOKEN_TTL = 12 * 60 * 60 * 1000;
const enc = new TextEncoder();

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
const fail = (msg, status = 400) => json({ error: msg }, status);

// ---------- token (HMAC-SHA256) ----------
const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const hmacKey = (secret) =>
  crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

async function makeToken(secret, u) {
  const body = b64u(enc.encode(JSON.stringify({ u, exp: Date.now() + TOKEN_TTL })));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body));
  return body + '.' + b64u(sig);
}
async function readToken(secret, header) {
  try {
    const t = (header || '').replace(/^Bearer /, '');
    const [body, sig] = t.split('.');
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64u(sig), enc.encode(body));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
    return p.exp > Date.now() && USERS[p.u] ? p.u : null;
  } catch { return null; }
}
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(x, y);
}

// ---------- util ----------
const clean = (v, max) => String(v ?? '').trim().slice(0, max);

const rowOut = (r) => ({
  id: r.id, rfq: r.rfq, company: r.company, moda: r.moda, term: r.term,
  pol: r.pol, pod: r.pod, desc: r.description, outcome: r.outcome,
  created: r.created, costAt: r.cost_at,
  file: r.file_name ? { name: r.file_name } : null,
});

// ---------- handler ----------
export async function onRequest({ request, env, params }) {
  if (!env.DB) return fail('Binding database "DB" belum dipasang di Cloudflare Pages.', 500);
  if (!env.AUTH_SECRET) return fail('Secret AUTH_SECRET belum diisi di Cloudflare Pages.', 500);

  const path = Array.isArray(params.path) ? params.path : [params.path].filter(Boolean);
  const method = request.method;

  // POST /api/login
  if (path[0] === 'login' && method === 'POST') {
    const b = await request.json().catch(() => ({}));
    const u = clean(b.u, 40).toLowerCase();
    const def = USERS[u];
    const expected = def && env[def.passVar];
    if (!def || !expected || !(await safeEqual(String(b.p ?? ''), expected)))
      return fail('Username atau password salah.', 401);
    return json({ token: await makeToken(env.AUTH_SECRET, u), user: u });
  }

  // semua endpoint lain wajib login
  const user = await readToken(env.AUTH_SECRET, request.headers.get('Authorization'));
  if (!user) return fail('Sesi habis, silakan login lagi.', 401);
  const role = USERS[user].role;

  if (path[0] !== 'rfqs') return fail('Endpoint tidak ditemukan.', 404);

  // GET /api/rfqs
  if (path.length === 1 && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM rfqs ORDER BY created DESC').all();
    return json(results.map(rowOut));
  }

  // POST /api/rfqs  (Sales)
  if (path.length === 1 && method === 'POST') {
    if (role !== 'sales') return fail('Hanya Sales yang bisa mengirim RFQ.', 403);
    const b = await request.json().catch(() => ({}));
    const d = {
      rfq: clean(b.rfq, 60), company: clean(b.company, 120), moda: clean(b.moda, 30),
      term: clean(b.term, 30), pol: clean(b.pol, 80), pod: clean(b.pod, 80), desc: clean(b.desc, 2000),
    };
    if (Object.values(d).some((v) => !v)) return fail('Semua kolom wajib diisi.');
    if (!MODA.includes(d.moda) || !TERM.includes(d.term)) return fail('Moda/layanan tidak valid.');
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    try {
      await env.DB.prepare(
        'INSERT INTO rfqs (id,rfq,company,moda,term,pol,pod,description,created) VALUES (?,?,?,?,?,?,?,?,?)'
      ).bind(id, d.rfq, d.company, d.moda, d.term, d.pol, d.pod, d.desc, Date.now()).run();
    } catch (e) {
      if (String(e).includes('UNIQUE')) return fail('Nomor RFQ sudah dipakai.', 409);
      throw e;
    }
    return json({ id }, 201);
  }

  const id = path[1];
  const exists = id && (await env.DB.prepare('SELECT id FROM rfqs WHERE id=?').bind(id).first());
  if (!exists) return fail('RFQ tidak ditemukan.', 404);

  // PATCH /api/rfqs/:id  -> keputusan customer (Sales)
  if (path.length === 2 && method === 'PATCH') {
    if (role !== 'sales') return fail('Hanya Sales yang bisa mengubah keputusan.', 403);
    const b = await request.json().catch(() => ({}));
    const outcome = b.outcome === 'deal' || b.outcome === 'lost' ? b.outcome : null;
    await env.DB.prepare('UPDATE rfqs SET outcome=? WHERE id=?').bind(outcome, id).run();
    return json({ ok: true, outcome });
  }

  // PUT /api/rfqs/:id/file  -> upload job sheet (Operation)
  // Body JSON: { name, mime, data(base64) }. Konversi base64 dilakukan di browser
  // supaya tidak memakan waktu CPU Worker (batas paket gratis sangat kecil).
  if (path[2] === 'file' && method === 'PUT') {
    if (role !== 'ops') return fail('Hanya Operation yang bisa upload job sheet.', 403);
    const b = await request.json().catch(() => null);
    if (!b || typeof b.data !== 'string' || !b.data) return fail('File kosong atau format tidak valid.');
    const name = clean(b.name, 200);
    if (!/\.(pdf|xlsx?|xlsm)$/i.test(name)) return fail('Format harus PDF atau Excel.');
    if (b.data.length > MAX_B64) return fail('Ukuran file maksimal 1,4 MB.', 413);
    const mime = clean(b.mime, 100) || 'application/octet-stream';
    await env.DB.batch([
      env.DB.prepare('INSERT OR REPLACE INTO files (rfq_id,mime,data) VALUES (?,?,?)').bind(id, mime, b.data),
      env.DB.prepare('UPDATE rfqs SET file_name=?, cost_at=? WHERE id=?').bind(name, Date.now(), id),
    ]);
    return json({ ok: true });
  }

  // GET /api/rfqs/:id/file  -> unduh job sheet (dikirim sebagai base64, didecode di browser)
  if (path[2] === 'file' && method === 'GET') {
    const f = await env.DB.prepare('SELECT mime,data FROM files WHERE rfq_id=?').bind(id).first();
    if (!f) return fail('Job sheet belum ada.', 404);
    return json({ mime: f.mime, data: f.data });
  }

  return fail('Metode tidak didukung.', 405);
}
