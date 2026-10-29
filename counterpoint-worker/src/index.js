// Coffee Beats <-> Counterpoint bridge (Cloudflare Worker)
//   POST /webhook  signed Counterpoint events  -> Firestore
//   POST /push     ops site (Firebase ID token, owner/manager) -> Counterpoint
//   POST /sync     owner-triggered full pull (same job as the 5-minute cron)
// Firestore collections written: counterpoint_sales, counterpoint_products,
// counterpoint_stock, counterpoint_locations, counterpoint_log

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uJson = (o) => b64u(enc.encode(JSON.stringify(o)));

// ── Counterpoint ───────────────────────────────────────────
async function cp(env, path, init = {}) {
  const res = await fetch(env.COUNTERPOINT_BASE + path, {
    ...init,
    headers: { Authorization: 'Bearer ' + env.COUNTERPOINT_API_KEY, 'Content-Type': 'application/json', ...(init.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Counterpoint ${res.status} ${path}: ${JSON.stringify(body).slice(0, 300)}`);
  return body;
}
const listOf = (b) => (Array.isArray(b) ? b : b.data || b.items || b.products || b.sales || b.locations || b.inventory || b.levels || []);

async function verifyWebhook(env, req, raw) {
  const sig = req.headers.get('x-counterpoint-signature') || '';
  const parts = Object.fromEntries(sig.split(',').map((p) => p.trim().split('=')));
  const t = Number(parts.t);
  if (!t || !parts.v1 || Math.abs(Date.now() / 1000 - t) > 300) return false;
  const key = await crypto.subtle.importKey('raw', enc.encode(env.COUNTERPOINT_WHSEC), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = hex(await crypto.subtle.sign('HMAC', key, enc.encode(`${t}.${raw}`)));
  if (mac.length !== parts.v1.length) return false;
  let diff = 0;
  for (let i = 0; i < mac.length; i++) diff |= mac.charCodeAt(i) ^ parts.v1.charCodeAt(i);
  return diff === 0;
}

// ── Firestore (REST, service-account auth) ─────────────────
let tokenCache = { value: null, exp: 0 };
async function gToken(env) {
  if (tokenCache.value && Date.now() < tokenCache.exp) return tokenCache.value;
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000);
  const head = b64uJson({ alg: 'RS256', typ: 'JWT' });
  const claim = b64uJson({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 });
  const pem = sa.private_key.replace(/-----[^-]+-----|\s/g, '');
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(`${head}.${claim}`)));
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${head}.${claim}.${sig}` }),
  });
  const j = await res.json();
  if (!j.access_token) throw new Error('Google auth failed: ' + JSON.stringify(j));
  tokenCache = { value: j.access_token, exp: Date.now() + 50 * 60 * 1000 };
  return j.access_token;
}

function fsVal(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === 'string') return { stringValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(fsVal) } };
  return { mapValue: { fields: Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fsVal(x)])) } };
}

// Upsert docs [{col, id, data}] in batches of 400
async function fsWrite(env, docs) {
  if (!docs.length) return;
  const token = await gToken(env);
  const base = `projects/${env.FIREBASE_PROJECT}/databases/(default)/documents`;
  for (let i = 0; i < docs.length; i += 400) {
    const writes = docs.slice(i, i + 400).map((d) => {
      const data = { ...d.data, synced_at: new Date().toISOString() };
      const w = { update: { name: `${base}/${d.col}/${encodeURIComponent(d.id)}`, fields: fsVal(data).mapValue.fields } };
      // merge: only touch the fields we send, so e.g. the list endpoint (no item lines) never wipes lines saved earlier
      if (d.merge) w.updateMask = { fieldPaths: Object.keys(data).map((k) => '`' + k + '`') };
      return w;
    });
    const res = await fetch(`https://firestore.googleapis.com/v1/${base}:commit`, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ writes }),
    });
    if (!res.ok) throw new Error('Firestore write failed: ' + (await res.text()).slice(0, 300));
  }
}

// ── Mapping Counterpoint -> Firestore docs ─────────────────
const saleDoc = (s) => ({ col: 'counterpoint_sales', id: String(s.id), data: { ...s, id: String(s.id) }, merge: true });
const productDoc = (p) => ({ col: 'counterpoint_products', id: String(p.id), data: p });

// ids (newest first) whose Firestore sale doc is missing or has no `lines` yet
async function salesMissingLines(env, ids) {
  if (!ids.length) return [];
  const token = await gToken(env);
  const base = `projects/${env.FIREBASE_PROJECT}/databases/(default)/documents`;
  const out = [];
  for (let i = 0; i < ids.length; i += 200) {
    const chunk = ids.slice(i, i + 200);
    const res = await fetch(`https://firestore.googleapis.com/v1/${base}:batchGet`, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ documents: chunk.map((id) => `${base}/counterpoint_sales/${encodeURIComponent(id)}`), mask: { fieldPaths: ['lines'] } }),
    });
    if (!res.ok) throw new Error('Firestore read failed: ' + (await res.text()).slice(0, 300));
    const rows = await res.json();
    rows.forEach((r) => {
      const name = (r.found && r.found.name) || r.missing;
      const id = decodeURIComponent(String(name).split('/').pop());
      if (r.missing || !(r.found.fields && r.found.fields.lines)) out.push(id);
    });
  }
  const order = new Map(ids.map((id, i) => [id, i]));
  return out.sort((a, b) => order.get(a) - order.get(b));
}

async function pullAll(env) {
  const docs = [];
  const [sales, products, locations] = await Promise.all([
    cp(env, '/sales?limit=200'), cp(env, '/products?view=catalog'), cp(env, '/locations'),
  ]);
  const saleList = listOf(sales);
  saleList.forEach((s) => docs.push(saleDoc(s)));
  // The sales LIST has no item lines (only GET /sales/:id does), and stock deduction in the ops app needs them.
  // Fetch the detail for sales whose Firestore doc still has no lines (newest first, capped for the subrequest limit).
  const missing = await salesMissingLines(env, saleList.map((s) => String(s.id)));
  const byId = Object.fromEntries(saleList.map((s) => [String(s.id), s]));
  for (const id of missing.slice(0, 40)) {
    try {
      const d = await cp(env, `/sales/${id}`);
      const full = d.data || d;
      if (full && Array.isArray(full.lines)) docs.push(saleDoc({ ...byId[id], ...full }));
    } catch (e) { /* retried on the next run */ }
  }
  listOf(products).forEach((p) => docs.push(productDoc(p)));
  const locs = listOf(locations);
  locs.forEach((l) => docs.push({ col: 'counterpoint_locations', id: String(l.id), data: l }));
  for (const l of locs) {
    const inv = listOf(await cp(env, `/inventory?locationId=${l.id}`));
    inv.forEach((r) => docs.push({ col: 'counterpoint_stock', id: `${l.id}_${r.sku || r.productId || r.id}`, data: { ...r, locationId: l.id } }));
  }
  await fsWrite(env, docs);
  await fsWrite(env, [{ col: 'counterpoint_log', id: 'last_sync', data: { at: new Date().toISOString(), counts: docs.length } }]);
  return docs.length;
}

async function handleEvent(env, evt) {
  const { event, data } = evt;
  if (event === 'sale.created' || event === 'refund.created') return fsWrite(env, [saleDoc({ ...data, kind: event })]);
  if (event.startsWith('product.')) return fsWrite(env, [productDoc({ ...data, archived: event === 'product.deleted' || !!data.archived })]);
  if (event === 'inventory.adjusted') return fsWrite(env, [{ col: 'counterpoint_stock', id: `${data.locationId}_${data.sku || data.productId}`, data }]);
  return fsWrite(env, [{ col: 'counterpoint_log', id: `evt_${Date.now()}`, data: { event, data } }]);
}

// ── Firebase ID-token check for calls from the ops site ────
let jwks = { keys: [], exp: 0 };
async function verifyFirebaseUser(env, req) {
  const tok = (req.headers.get('Authorization') || '').replace(/^Bearer /, '');
  const [h, p, s] = tok.split('.');
  if (!s) return null;
  if (Date.now() > jwks.exp) {
    const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
    jwks = { keys: (await r.json()).keys, exp: Date.now() + 3600e3 };
  }
  const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')));
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const sig = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, enc.encode(`${h}.${p}`)))) return null;
  const claims = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
  if (claims.aud !== env.FIREBASE_PROJECT || claims.exp < Date.now() / 1000) return null;
  return claims;
}

// ── Router ─────────────────────────────────────────────────
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = req.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGINS.split(',').includes(origin) ? origin : '',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
    };
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json', ...cors } });
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });

    try {
      if (url.pathname === '/webhook' && req.method === 'POST') {
        const raw = await req.text();
        if (!(await verifyWebhook(env, req, raw))) return json({ error: 'bad signature' }, 401);
        await handleEvent(env, JSON.parse(raw));
        return json({ ok: true });
      }

      if (url.pathname === '/sync' || url.pathname === '/push') {
        const user = await verifyFirebaseUser(env, req);
        const allowed = ['owner', 'manager', 'accountant'];
        if (!user || !allowed.includes(user.role)) return json({ error: 'not allowed' }, 403);
        if (url.pathname === '/sync') return json({ ok: true, docs: await pullAll(env) });

        // /push  { type: 'product'|'customer'|'sale', payload: {...} }
        if (user.role !== 'owner') return json({ error: 'only the owner can write to Counterpoint' }, 403);
        const { type, payload } = await req.json();
        const path = { product: '/products', customer: '/customers', sale: '/sales' }[type];
        if (!path) return json({ error: 'unknown type' }, 400);
        const result = await cp(env, path, { method: 'POST', body: JSON.stringify(payload) });
        await fsWrite(env, [{ col: 'counterpoint_log', id: `push_${Date.now()}`, data: { type, by: user.email || user.user_id, result } }]);
        return json({ ok: true, dryRun: !!result.dryRun, result });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: String(e.message || e) }, 500);
    }
  },

  async scheduled(_evt, env, ctx) {
    ctx.waitUntil(pullAll(env));
  },
};
