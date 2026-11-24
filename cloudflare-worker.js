// Tylos Labour — shared storage API (Cloudflare Worker + KV namespace bound as DB)
// Stores: settings (staff, rates, rules, options), agency templates, latest workbook.
// Auth: every request carries header "X-Tylos-Key: <password>"; checked against a SHA-256 hash in KV.

const DEFAULT_PW_HASH = '2f2b7e88442fbc58a3995ff4d32e69615bac6e180c14583ec403ac5594e5dff3'; // *Tylos2026
const ALLOW_PASSWORD_CHANGE = false; // set to true to allow changing the shared password from the site
const ALLOWED_ORIGINS = ['https://tylos-labour.jaemi.uk', 'https://jaemi.uk', 'https://www.jaemi.uk', 'http://127.0.0.1:8765'];

async function sha256(t) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function cors(req) {
  const o = req.headers.get('Origin') || '';
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'X-Tylos-Key, Content-Type, X-Name, X-Base-Version, X-Last-Date, X-By',
    'Access-Control-Expose-Headers': 'X-Name, X-Version, X-Last-Date, X-By',
    'Access-Control-Max-Age': '86400', 'Vary': 'Origin', 'Cache-Control': 'no-store'
  };
}
const json = (req, obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...cors(req), 'Content-Type': 'application/json' } });

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(req) });
    const url = new URL(req.url); const path = url.pathname.replace(/\/+$/, '') || '/';
    if (path === '/' || path === '/health') return json(req, { ok: true, service: 'tylos-labour-api' });
    if (!env.DB) return json(req, { error: 'Storage (KV binding "DB") is not connected to this Worker.' }, 500);

    // ---- auth (with simple brute-force slow-down)
    const key = req.headers.get('X-Tylos-Key') || '';
    const stored = (await env.DB.get('auth:pwHash')) || DEFAULT_PW_HASH;
    if (!key || (await sha256(key)) !== stored) {
      await new Promise(r => setTimeout(r, 800));
      return json(req, { error: 'Wrong password.' }, 401);
    }

    // ---- routes
    if (path === '/login') return json(req, { ok: true, defaultPassword: stored === DEFAULT_PW_HASH });

    if (path === '/password' && req.method === 'POST') {
      if (!ALLOW_PASSWORD_CHANGE) return json(req, { error: 'Password changes are switched off.' }, 403);
      const { newPassword } = await req.json();
      if (!newPassword || String(newPassword).length < 6) return json(req, { error: 'Use at least 6 characters.' }, 400);
      await env.DB.put('auth:pwHash', await sha256(String(newPassword)));
      return json(req, { ok: true });
    }

    if (path === '/state' && req.method === 'GET') {
      const [settingsMeta, wbMeta, tAir, tIns] = await Promise.all([
        env.DB.get('settings:meta', 'json'), env.DB.get('workbook:meta', 'json'),
        env.DB.get('template:Air:meta', 'json'), env.DB.get('template:Insight:meta', 'json')]);
      return json(req, { settings: settingsMeta, workbook: wbMeta, templates: { Air: tAir, Insight: tIns } });
    }

    if (path === '/settings') {
      if (req.method === 'GET') { const s = await env.DB.get('settings'); return new Response(s || 'null', { headers: { ...cors(req), 'Content-Type': 'application/json' } }); }
      if (req.method === 'PUT') {
        const body = await req.text(); try { const j = JSON.parse(body); if (!j.roster || !j.profiles) throw 0; } catch (e) { return json(req, { error: 'Invalid settings.' }, 400); }
        const meta = { version: Date.now(), by: req.headers.get('X-By') || '' };
        await env.DB.put('settings', body); await env.DB.put('settings:meta', JSON.stringify(meta));
        return json(req, { ok: true, ...meta });
      }
    }

    const tmm = /^\/template\/([^/]{1,60})\/meta$/.exec(path);
    if (tmm && req.method === 'GET') { const meta = await env.DB.get('template:' + decodeURIComponent(tmm[1]) + ':meta', 'json'); return meta ? json(req, meta) : json(req, { error: 'No template.' }, 404); }
    const tm = /^\/template\/([^/]{1,60})$/.exec(path);
    if (tm) {
      const g = decodeURIComponent(tm[1]);
      if (req.method === 'GET') {
        const [b, meta] = await Promise.all([env.DB.get('template:' + g, 'arrayBuffer'), env.DB.get('template:' + g + ':meta', 'json')]);
        if (!b) return json(req, { error: 'No template.' }, 404);
        return new Response(b, { headers: { ...cors(req), 'Content-Type': 'application/octet-stream', 'X-Name': encodeURIComponent(meta?.name || g + '.xlsx'), 'X-Version': String(meta?.version || 0) } });
      }
      if (req.method === 'PUT') {
        const b = await req.arrayBuffer(); if (b.byteLength < 1000) return json(req, { error: 'Empty file.' }, 400);
        const meta = { name: decodeURIComponent(req.headers.get('X-Name') || g + '.xlsx'), version: Date.now(), size: b.byteLength };
        await env.DB.put('template:' + g, b); await env.DB.put('template:' + g + ':meta', JSON.stringify(meta));
        return json(req, { ok: true, ...meta });
      }
    }

    if (path === '/workbook/previous' && req.method === 'GET') {
      const [b, meta] = await Promise.all([env.DB.get('workbook:prev', 'arrayBuffer'), env.DB.get('workbook:prev:meta', 'json')]);
      if (!b) return json(req, { error: 'No previous copy.' }, 404);
      return new Response(b, { headers: { ...cors(req), 'Content-Type': 'application/octet-stream', 'X-Name': encodeURIComponent(meta?.name || 'previous.xlsx'), 'X-Version': String(meta?.version || 0), 'X-Last-Date': meta?.lastDate || '', 'X-By': encodeURIComponent(meta?.by || '') } });
    }
    if (path === '/workbook') {
      if (req.method === 'GET') {
        const [b, meta] = await Promise.all([env.DB.get('workbook', 'arrayBuffer'), env.DB.get('workbook:meta', 'json')]);
        if (!b) return json(req, { error: 'No workbook yet.' }, 404);
        return new Response(b, { headers: { ...cors(req), 'Content-Type': 'application/octet-stream', 'X-Name': encodeURIComponent(meta?.name || 'Labour time sheet and task record.xlsx'), 'X-Version': String(meta?.version || 0), 'X-Last-Date': meta?.lastDate || '', 'X-By': encodeURIComponent(meta?.by || '') } });
      }
      if (req.method === 'PUT') {
        const current = await env.DB.get('workbook:meta', 'json');
        const base = req.headers.get('X-Base-Version');
        if (current && base !== 'force' && String(current.version) !== String(base)) {
          return json(req, { error: 'conflict', current }, 409);
        }
        const b = await req.arrayBuffer(); if (b.byteLength < 1000) return json(req, { error: 'Empty file.' }, 400);
        const meta = { name: decodeURIComponent(req.headers.get('X-Name') || 'Labour time sheet and task record.xlsx'), version: Date.now(), size: b.byteLength, lastDate: req.headers.get('X-Last-Date') || '', by: decodeURIComponent(req.headers.get('X-By') || '') };
        // keep the previous copy as a one-step backup
        const prev = await env.DB.get('workbook', 'arrayBuffer');
        if (prev && current) { await env.DB.put('workbook:prev', prev); await env.DB.put('workbook:prev:meta', JSON.stringify(current)); }
        await env.DB.put('workbook', b); await env.DB.put('workbook:meta', JSON.stringify(meta));
        return json(req, { ok: true, ...meta });
      }
    }
    return json(req, { error: 'Not found.' }, 404);
  }
};
