// Cloudflare Pages Function: API untuk Dashboard Freight Forwarder
// Binding yang dibutuhkan : DB (D1)
// Secret yang dibutuhkan  : AUTH_SECRET, PASS_SALES, PASS_OPERATION, PASS_PROJECTCONTROL

const USERS = {
  sales:          { role: 'sales', passVar: 'PASS_SALES' },
  operation:      { role: 'ops',   passVar: 'PASS_OPERATION' },
  projectcontrol: { role: 'pc',    passVar: 'PASS_PROJECTCONTROL' },
};
const MODA = ['Forwarding', 'Kepabeanan', 'Trucking', 'Sea Freight']; // COA
const TERM = ['Door to Door', 'Door to Port', 'Port to Door', 'Port to Port', 'Customs Clearance'];
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

const rowOut = (r, role) => ({
  id: r.id, rfq: r.rfq, company: r.company, moda: r.moda, term: r.term, pol: r.pol, pod: r.pod,
  desc: r.description, outcome: r.outcome, created: r.created, costAt: r.cost_at,
  file: r.file_name ? { name: r.file_name } : null,
  salesName: r.sales_name, opsName: r.ops_name, takenAt: r.taken_at, quoteAt: r.quote_at,
  decidedAt: r.decided_at, lostReason: r.lost_reason, waiting: !!r.waiting,
  cost: role === 'ops' ? null : r.cost, revenue: role === 'ops' ? null : r.revenue, // Operation tidak melihat keuangan
  salesFile: role !== 'ops' && r.sales_file_name ? { name: r.sales_file_name } : null,
  // pesan/dokumen baru dari unit lawan sejak terakhir dibuka
  unread: role === 'sales' ? (r.ln_ops || 0) > (r.sales_seen || 0)
        : role === 'ops' ? Math.max(r.ln_sales || 0, r.ln_att || 0) > (r.ops_seen || 0) : false,
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
    const { results } = await env.DB.prepare(
      `SELECT r.*,
        (SELECT MAX(at) FROM notes n WHERE n.rfq_id=r.id AND n.role='ops') AS ln_ops,
        (SELECT MAX(at) FROM notes n WHERE n.rfq_id=r.id AND n.role='sales') AS ln_sales,
        (SELECT MAX(at) FROM attachments a WHERE a.rfq_id=r.id) AS ln_att
       FROM rfqs r ORDER BY r.created DESC`).all();
    return json(results.map((r) => rowOut(r, role)));
  }

  // POST /api/rfqs  (Sales)
  if (path.length === 1 && method === 'POST') {
    if (role !== 'sales') return fail('Hanya Sales yang bisa mengirim RFQ.', 403);
    const b = await request.json().catch(() => ({}));
    const d = {
      rfq: clean(b.rfq, 60), company: clean(b.company, 120), moda: clean(b.moda, 30), term: clean(b.term, 30),
      pol: clean(b.pol, 80), pod: clean(b.pod, 80), desc: clean(b.desc, 2000), sales: clean(b.salesName, 60),
    };
    if (Object.values(d).some((v) => !v)) return fail('Semua kolom wajib diisi (termasuk nama Sales).');
    if (!MODA.includes(d.moda) || !TERM.includes(d.term)) return fail('COA/layanan tidak valid.');
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    try {
      await env.DB.prepare(
        'INSERT INTO rfqs (id,rfq,company,moda,term,pol,pod,description,created,sales_name) VALUES (?,?,?,?,?,?,?,?,?,?)'
      ).bind(id, d.rfq, d.company, d.moda, d.term, d.pol, d.pod, d.desc, Date.now(), d.sales).run();
    } catch (e) {
      if (String(e).includes('UNIQUE')) return fail('Nomor RFQ sudah dipakai.', 409);
      throw e;
    }
    return json({ id }, 201);
  }

  const id = path[1];
  const exists = id && (await env.DB.prepare('SELECT id FROM rfqs WHERE id=?').bind(id).first());
  if (!exists) return fail('RFQ tidak ditemukan.', 404);

  // PATCH /api/rfqs/:id  { action: take | waiting | quote | deal | lost | undo }
  if (path.length === 2 && method === 'PATCH') {
    const b = await request.json().catch(() => ({}));
    const now = Date.now(), A = b.action, q = (sql, ...v) => env.DB.prepare(sql).bind(...v, id);
    let st;
    if (A === 'take' && role === 'ops') {
      const n = clean(b.name, 60); if (!n) return fail('Nama PIC wajib diisi.');
      st = q('UPDATE rfqs SET ops_name=?, taken_at=COALESCE(taken_at,?), waiting=0 WHERE id=?', n, now);
    } else if (A === 'waiting' && role !== 'pc') st = q('UPDATE rfqs SET waiting=? WHERE id=?', b.on ? 1 : 0);
    else if (A === 'seen' && role !== 'pc') st = q(role === 'sales' ? 'UPDATE rfqs SET sales_seen=? WHERE id=?' : 'UPDATE rfqs SET ops_seen=? WHERE id=?', now);
    else if (A === 'quote' && role === 'sales') st = q('UPDATE rfqs SET quote_at=COALESCE(quote_at,?) WHERE id=?', now);
    else if (A === 'deal' && role === 'sales') {
      const c = Number(b.cost), v = Number(b.revenue);
      if (b.cost === '' || b.revenue === '' || !(c >= 0) || !(v >= 0)) return fail('Cost dan revenue harus berupa angka.');
      const cur = await env.DB.prepare('SELECT outcome, sales_file_name FROM rfqs WHERE id=?').bind(id).first();
      if (cur.outcome !== 'deal' && !cur.sales_file_name) return fail('Upload job sheet sales terlebih dahulu sebelum menyimpan deal.');
      st = q("UPDATE rfqs SET outcome='deal', decided_at=COALESCE(decided_at,?), cost=?, revenue=?, lost_reason=NULL WHERE id=?", now, c, v);
    } else if (A === 'lost' && role === 'sales') {
      const r = clean(b.reason, 500); if (!r) return fail('Alasan tidak deal wajib diisi.');
      st = q("UPDATE rfqs SET outcome='lost', decided_at=COALESCE(decided_at,?), lost_reason=? WHERE id=?", now, r);
    } else if (A === 'undo' && role === 'sales') st = q('UPDATE rfqs SET outcome=NULL, decided_at=NULL, lost_reason=NULL WHERE id=?');
    else return fail('Aksi tidak diizinkan untuk unit Anda.', 403);
    await st.run();
    return json({ ok: true });
  }

  // Catatan Operation <-> Sales
  if (path[2] === 'notes') {
    if (method === 'GET') {
      const { results } = await env.DB.prepare('SELECT author,role,text,at FROM notes WHERE rfq_id=? ORDER BY at').bind(id).all();
      return json(results);
    }
    if (method === 'POST' && role !== 'pc') {
      const b = await request.json().catch(() => ({}));
      const text = clean(b.text, 1000), author = clean(b.author, 60);
      if (!text || !author) return fail('Nama dan isi catatan wajib diisi.');
      const ops = [env.DB.prepare('INSERT INTO notes (rfq_id,author,role,text,at) VALUES (?,?,?,?,?)').bind(id, author, role, text, Date.now())];
      if (role === 'ops' && b.ask) ops.push(env.DB.prepare('UPDATE rfqs SET waiting=1 WHERE id=?').bind(id));
      if (role === 'sales') ops.push(env.DB.prepare('UPDATE rfqs SET waiting=0 WHERE id=?').bind(id));
      await env.DB.batch(ops);
      return json({ ok: true }, 201);
    }
  }

  // Job sheet sales (diunggah Sales, dilihat Sales & Project Control)
  if (path[2] === 'salesfile' && role !== 'ops') {
    if (method === 'PUT') {
      if (role !== 'sales') return fail('Hanya Sales yang bisa upload job sheet sales.', 403);
      const b = await request.json().catch(() => null), name = clean(b && b.name, 200);
      if (!b || typeof b.data !== 'string' || !b.data) return fail('File kosong.');
      if (!/\.(pdf|xlsx?|xlsm)$/i.test(name)) return fail('Format harus PDF atau Excel.');
      if (b.data.length > MAX_B64) return fail('Ukuran file maksimal 1,4 MB.', 413);
      await env.DB.batch([
        env.DB.prepare('INSERT OR REPLACE INTO sales_files (rfq_id,mime,data) VALUES (?,?,?)').bind(id, clean(b.mime, 100) || 'application/octet-stream', b.data),
        env.DB.prepare('UPDATE rfqs SET sales_file_name=? WHERE id=?').bind(name, id),
      ]);
      return json({ ok: true });
    }
    if (method === 'GET') {
      const f = await env.DB.prepare('SELECT mime,data FROM sales_files WHERE rfq_id=?').bind(id).first();
      return f ? json(f) : fail('Job sheet sales belum ada.', 404);
    }
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

  // Lampiran pendukung RFQ (maks 10 file, 1 MB per file)
  if (path[2] === 'attach') {
    if (method === 'GET' && !path[3]) {
      const { results } = await env.DB.prepare('SELECT id,name,size FROM attachments WHERE rfq_id=? ORDER BY id').bind(id).all();
      return json(results);
    }
    if (method === 'GET') {
      const f = await env.DB.prepare('SELECT mime,data FROM attachments WHERE id=? AND rfq_id=?').bind(path[3], id).first();
      return f ? json(f) : fail('Lampiran tidak ditemukan.', 404);
    }
    if (method === 'POST') {
      if (role !== 'sales') return fail('Hanya Sales yang bisa menambah lampiran.', 403);
      const b = await request.json().catch(() => null), name = clean(b && b.name, 200);
      if (!b || typeof b.data !== 'string' || !b.data) return fail('File kosong.');
      if (!/\.(pdf|png|jpe?g|docx|xlsx|csv|txt)$/i.test(name)) return fail('Format lampiran tidak didukung.');
      if (b.data.length > 1.4e6) return fail('Ukuran lampiran maksimal 1 MB.', 413);
      const c = await env.DB.prepare('SELECT COUNT(*) n FROM attachments WHERE rfq_id=?').bind(id).first();
      if (c.n >= 10) return fail('Maksimal 10 lampiran per RFQ.');
      await env.DB.prepare('INSERT INTO attachments (rfq_id,name,mime,size,data,at) VALUES (?,?,?,?,?,?)')
        .bind(id, name, clean(b.mime, 100) || 'application/octet-stream', Math.round(b.data.length * 3 / 4), b.data, Date.now()).run();
      return json({ ok: true }, 201);
    }
  }

  return fail('Metode tidak didukung.', 405);
}
