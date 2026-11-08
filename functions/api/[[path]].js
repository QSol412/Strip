// Strip online posting: stories, chapters, page images and profiles, stored in R2.
// Cloudflare Pages Function, served at /api/*  (the votes/comments function in
// functions/api/social/ is more specific, so it keeps handling /api/social/*).
//
// Needs the same two settings as votes/comments (Pages project, Settings):
//   Bindings   -> R2 bucket,  variable name: SYNC_BUCKET
//   Variables  -> GOOGLE_CLIENT_ID   (your Google sign-in client ID)
//
// Reading is open to everyone. Posting, editing and deleting need a Google sign-in
// (Authorization: Bearer <Google credential>) and only work on your own stories.
//
// Routes the app uses
//   GET    config                    -> {clientId}
//   GET    stories                   -> [ {id,name,genre,syn,thumb,author,authorUid,updated,chapters:[{id,name,pages}]} ]
//   PUT    stories/:id               -> create/update a story's details + chapter list
//   DELETE stories/:id               -> take a story offline (removes its data)
//   DELETE stories/:id/data          -> clear a story's uploaded chapters and images (before re-posting)
//   PUT/GET stories/:id/ch/:cid      -> {j}  chapter pages as a JSON string
//   PUT/GET stories/:id/img/:key     -> {d}  one page layer image as a data: URL
//   PUT    me                        -> save your profile {name,bio,av}
//   GET    profiles/:uid             -> {name,bio,av,stories:[...]}
//   GET    ads                       -> []

const TE = new TextEncoder(), TD = new TextDecoder();
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const ID = /^[\w-]{1,64}$/, KEY = /^[\w-]{1,80}$/;
const cut = (v, n) => String(v == null ? '' : v).slice(0, n);
const imgOk = (v, max) => typeof v === 'string' && v.length <= max && /^data:image\/(webp|png|jpeg|jpg);base64,/.test(v);
const IX = 'online/index.json';
const MAX_STORY_NAME = 200, MAX_CHAPTER_NAME = 120;   // story / chapter titles (was 80)

async function verifyGoogle(tok, env) {
  const [h, p, sig] = tok.split('.');
  if (!sig) throw 0;
  const head = JSON.parse(TD.decode(unb64u(h))), pl = JSON.parse(TD.decode(unb64u(p)));
  const jw = await (await fetch('https://www.googleapis.com/oauth2/v3/certs', { cf: { cacheTtl: 3600, cacheEverything: true } })).json();
  const jwk = jw.keys.find(k => k.kid === head.kid);
  if (!jwk) throw 0;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(sig), TE.encode(h + '.' + p));
  if (!ok || pl.aud !== env.GOOGLE_CLIENT_ID || !/^(https:\/\/)?accounts\.google\.com$/.test(pl.iss) || pl.exp * 1000 < Date.now()) throw 0;
  return { sub: pl.sub, email: (pl.email_verified === true || pl.email_verified === 'true') ? String(pl.email || '').toLowerCase() : '' };
}

const CID = /^[\w-]{1,24}$/;
const MAX_COMMENTS = 300, MAX_TEXT = 500;

// Count votes under a prefix. Result is keyed by whatever sits between the prefix and the voter id.
async function scan(R, prefix, me) {
  const out = {}; let cur, n = 0;
  do {
    const l = await R.list({ prefix, cursor: cur, include: ['customMetadata'] });
    for (const o of l.objects) {
      const p = o.key.slice(prefix.length).split('/'), voter = p.pop(), id = p.join('/');
      const v = +(o.customMetadata && o.customMetadata.v) || 0;
      const x = out[id] || (out[id] = { up: 0, dn: 0, mine: 0 });
      if (v > 0) x.up++; else if (v < 0) x.dn++;
      if (me && voter === me) x.mine = v;
    }
    cur = l.truncated ? l.cursor : null;
  } while (cur && ++n < 20);
  return out;
}

// ---- votes + comments (/api/social/*) -- handled here so it works even if the
// separate functions/api/social/ file is missing or not picked up by Pages.
// Number of reports per comment in one thread (one report per signed-in user).
async function reports(R, story) {
  const pre = 'social/r/' + story + '/', out = {}; let cur, n = 0;
  do {
    const l = await R.list({ prefix: pre, cursor: cur });
    for (const o of l.objects) { const id = o.key.slice(pre.length).split('/')[0]; out[id] = (out[id] || 0) + 1; }
    cur = l.truncated ? l.cursor : null;
  } while (cur && ++n < 20);
  return out;
}
const HIDE_AT = 3;   // reports before a comment is hidden from everyone but its author and the admin

async function social({ request, env, m, path, me, meEmail, R }) {
  const needMe = () => J({ error: 'Please sign in again.' }, 401);
  const none = { up: 0, dn: 0, mine: 0 };
  // Roles: ADMIN_UID (env) = owners, always admin. Admins can hand out 'admin' or 'mod' (saved in R2).
  // mod = can delete comments and see report counts. admin = same, plus manages roles.
  const owners = String(env.ADMIN_UID || '').split(',').map(x => x.trim()).filter(Boolean), RK = 'online/roles.json';
  let roles = {}; try { const o = await R.get(RK); roles = o ? await o.json() : {}; } catch (e) { roles = {}; }
  // Owner emails: the first time one of these Google accounts signs in, it is saved as a permanent owner/admin.
  const ownerEmails = ['stripcomics412@gmail.com', ...String(env.ADMIN_EMAIL || '').split(',')].map(x => x.trim().toLowerCase()).filter(Boolean);
  if (me && meEmail && ownerEmails.includes(meEmail) && roles[me] !== 'owner') {
    roles[me] = 'owner';
    await R.put(RK, JSON.stringify(roles), { httpMetadata: { contentType: 'application/json' } });
  }
  const roleOf = u => !u ? '' : (owners.includes(u) || roles[u] === 'owner') ? 'admin' : (roles[u] || '');
  const role = roleOf(me), isAdmin = role === 'admin', isStaff = !!role;

  if (m === 'PUT' && path[0] === 'roles') {
    if (!me) return needMe();
    if (!isAdmin) return J({ error: 'Only admins can change roles.' }, 403);
    let b; try { b = await request.json(); } catch (e) { return J({ error: 'Bad request.' }, 400); }
    const uid = String(b.uid || ''), r = String(b.role || '');
    if (!ID.test(uid) || !['admin', 'mod', ''].includes(r)) return J({ error: 'Bad request.' }, 400);
    if (owners.includes(uid) || roles[uid] === 'owner') return J({ error: 'The owner always stays an admin.' }, 400);
    if (r) roles[uid] = r; else delete roles[uid];
    await R.put(RK, JSON.stringify(roles), { httpMetadata: { contentType: 'application/json' } });
    return J({ ok: 1 });
  }

  if (m === 'GET' && path[0] === 'tally') return J(await scan(R, 'social/v/', me));

  if (m === 'PUT' && path[0] === 'vote') {
    if (!me) return needMe();
    let b; try { b = await request.json(); } catch (e) { return J({ error: 'Bad request.' }, 400); }
    const id = String(b.id || ''), v = +b.v;
    if (![1, -1, 0].includes(v)) return J({ error: 'Bad vote.' }, 400);
    let key, pre;
    if (/^[se]_[\w-]{1,62}$/.test(id)) { pre = 'social/v/' + id + '/'; key = pre + me; }
    else if (/^c_[\w-]{1,22}$/.test(id) && ID.test(b.story || '')) { pre = 'social/cv/' + b.story + '/' + id.slice(2) + '/'; key = pre + me; }
    else return J({ error: 'Bad vote.' }, 400);
    if (v) await R.put(key, '', { customMetadata: { v: String(v) } }); else await R.delete(key);
    return J((await scan(R, pre, me))[''] || none);
  }

  if (path[0] === 'comments' && ID.test(path[1] || '')) {
    const story = path[1], ck = 'social/c/' + story + '.json';
    const load = async () => { const o = await R.get(ck); try { return o ? await o.json() : []; } catch (e) { return []; } };
    if (m === 'GET' && path.length === 2) {
      const all = await load(), votes = await scan(R, 'social/cv/' + story + '/', me), rc = await reports(R, story);
      return J({ role, comments: all.slice(-200).reverse().map(c => {
        const n = rc[c.id] || 0, hide = !isStaff && c.uid !== me && n >= HIDE_AT;
        return { ...c, ...(votes[c.id] || none), ...(isStaff ? { rc: n } : {}), ...(roleOf(c.uid) ? { staff: roleOf(c.uid) } : {}), ...(hide ? { text: '', hidden: 1 } : {}) };
      }) });
    }
    if (m === 'POST' && path.length === 4 && CID.test(path[2]) && path[3] === 'report') {
      if (!me) return needMe();
      const c = (await load()).find(x => x.id === path[2]);
      if (!c) return J({ error: 'That comment is gone.' }, 404);
      if (c.uid === me) return J({ error: 'You cannot report your own comment.' }, 400);
      await R.put('social/r/' + story + '/' + c.id + '/' + me, '');
      return J({ ok: 1 });
    }
    if (m === 'POST' && path.length === 2) {
      if (!me) return needMe();
      let b; try { b = await request.json(); } catch (e) { return J({ error: 'Bad request.' }, 400); }
      const text = String(b.text || '').trim().slice(0, MAX_TEXT), name = String(b.name || '').trim().slice(0, 30);
      if (!text) return J({ error: 'Write something first.' }, 400);
      const all = await load();
      let parent = '', to = '';
      if (b.parent) {
        const p = all.find(x => x.id === String(b.parent));
        if (!p) return J({ error: 'That comment is gone.' }, 404);
        parent = p.parent || p.id;                      // replies stay one level deep
        to = String(b.to || '').trim().slice(0, 30);
      }
      const last = all.filter(c => c.uid === me).pop();
      if (last && Date.now() - last.t < 3000) return J({ error: 'Slow down a little.' }, 429);
      const c = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), uid: me, name, text, t: Date.now(), ...(parent ? { parent, to } : {}) };
      all.push(c);
      await R.put(ck, JSON.stringify(all.slice(-MAX_COMMENTS)), { httpMetadata: { contentType: 'application/json' } });
      return J({ ok: 1, id: c.id });
    }
    if (m === 'DELETE' && path.length === 3 && CID.test(path[2])) {
      if (!me) return needMe();
      const all = await load();
      if (!all.some(c => c.id === path[2] && (c.uid === me || isStaff))) return J({ error: 'You can only delete your own comments.' }, 403);
      const gone = new Set([path[2], ...all.filter(c => c.parent === path[2]).map(c => c.id)]);   // its replies go with it
      await R.put(ck, JSON.stringify(all.filter(c => !gone.has(c.id))), { httpMetadata: { contentType: 'application/json' } });
      for (const id of gone) {
        for (const pre of ['social/cv/', 'social/r/']) {
          const l = await R.list({ prefix: pre + story + '/' + id + '/' });
          if (l.objects.length) await R.delete(l.objects.map(o => o.key));
        }
      }
      return J({ ok: 1 });
    }
  }
  return J({ error: 'Not found.' }, 404);
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url), m = request.method;
  const path = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  const R = env.SYNC_BUCKET, ready = !!(R && env.GOOGLE_CLIENT_ID);

  if (m === 'GET' && path[0] === 'config' && path.length === 1) return J({ clientId: ready ? env.GOOGLE_CLIENT_ID : '' });
  if (m === 'GET' && path[0] === 'ads') return J([]);
  if (!ready) {
    const missing = [!R && 'R2 bucket binding named SYNC_BUCKET', !env.GOOGLE_CLIENT_ID && 'variable named GOOGLE_CLIENT_ID'].filter(Boolean);
    return J({ error: 'Online posting is not set up on the server yet. Missing: ' + missing.join(' and ') + '.' }, 503);
  }

  const readIx = async () => { const o = await R.get(IX); try { return o ? await o.json() : {}; } catch (e) { return {}; } };
  const writeIx = ix => R.put(IX, JSON.stringify(ix), { httpMetadata: { contentType: 'application/json' } });
  const bearer = (request.headers.get('Authorization') || '').replace(/^Bearer /, '');
  let me = null, meEmail = '';
  if (bearer) { try { const v = await verifyGoogle(bearer, env); me = v.sub; meEmail = v.email; } catch (e) { me = null; } }
  const needMe = () => J({ error: 'Please sign in again.' }, 401);
  if (path[0] === 'social') return social({ request, env, m, path: path.slice(1), me, meEmail, R });
  const body = async () => { try { return await request.json(); } catch (e) { return null; } };
  const wipe = async id => {
    let cur;
    do {
      const l = await R.list({ prefix: 'online/d/' + id + '/', cursor: cur });
      if (l.objects.length) await R.delete(l.objects.map(o => o.key));
      cur = l.truncated ? l.cursor : null;
    } while (cur);
  };
  const store = (key, obj) => R.put(key, JSON.stringify(obj), { httpMetadata: { contentType: 'application/json' } });
  const send = async key => { const o = await R.get(key); return o ? new Response(o.body, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }) : J({ error: 'Not found.' }, 404); };

  // ---- profiles
  if (path[0] === 'me' && path.length === 1 && m === 'PUT') {
    if (!me) return needMe();
    const b = await body(); if (!b) return J({ error: 'Bad request.' }, 400);
    await store('online/me/' + me + '.json', { name: cut(b.name, 30), bio: cut(b.bio, 160), av: imgOk(b.av, 150000) ? b.av : '' });
    return J({ ok: 1 });
  }
  if (path[0] === 'profiles' && ID.test(path[1] || '') && m === 'GET') {
    const o = await R.get('online/me/' + path[1] + '.json'); let p = {};
    try { p = o ? await o.json() : {}; } catch (e) { p = {}; }
    const ix = await readIx();
    return J({ name: p.name || '', bio: p.bio || '', av: p.av || '', stories: Object.values(ix).filter(s => s.authorUid === path[1]).sort((a, b) => b.updated - a.updated) });
  }

  // ---- stories
  if (path[0] === 'stories' && path.length === 1 && m === 'GET') {
    return J(Object.values(await readIx()).sort((a, b) => b.updated - a.updated));
  }
  if (path[0] === 'stories' && ID.test(path[1] || '')) {
    const id = path[1];

    // public reads
    if (m === 'GET' && path[2] === 'ch' && ID.test(path[3] || '') && path.length === 4) return send('online/d/' + id + '/ch/' + path[3] + '.json');
    if (m === 'GET' && path[2] === 'img' && KEY.test(path[3] || '') && path.length === 4) return send('online/d/' + id + '/img/' + path[3] + '.json');

    // everything else changes data: sign-in + must be the story's owner
    if (!me) return needMe();
    const ix = await readIx(), cur = ix[id];
    if (cur && cur.authorUid !== me) return J({ error: 'This story belongs to someone else.' }, 403);

    if (m === 'PUT' && path.length === 2) {
      const b = await body(); if (!b) return J({ error: 'Bad request.' }, 400);
      const chapters = (Array.isArray(b.chapters) ? b.chapters : []).slice(0, 200)
        .filter(c => c && ID.test(String(c.id || ''))).map(c => ({ id: String(c.id), name: cut(c.name, MAX_CHAPTER_NAME), pages: Math.max(0, Math.min(999, +c.pages || 0)) }));
      ix[id] = { id, name: cut(b.name, MAX_STORY_NAME), genre: cut(b.genre, 40), syn: cut(b.syn, 600), thumb: imgOk(b.thumb, 300000) ? b.thumb : '', author: cut(b.author, 30), authorUid: me, updated: Date.now(), chapters };
      await writeIx(ix);
      return J({ ok: 1 });
    }
    if (m === 'DELETE' && path.length === 2) {
      await wipe(id);
      if (cur) { delete ix[id]; await writeIx(ix); }
      return J({ ok: 1 });
    }
    if (m === 'DELETE' && path[2] === 'data' && path.length === 3) {
      if (cur) await wipe(id);
      return J({ ok: 1 });
    }
    if (!cur) return J({ error: 'Post the story details first.' }, 404);
    if (m === 'PUT' && path[2] === 'ch' && ID.test(path[3] || '') && path.length === 4) {
      const b = await body();
      if (!b || typeof b.j !== 'string' || b.j.length > 4e6) return J({ error: 'Chapter is too large.' }, 413);
      try { JSON.parse(b.j); } catch (e) { return J({ error: 'Bad chapter data.' }, 400); }
      await store('online/d/' + id + '/ch/' + path[3] + '.json', { j: b.j });
      return J({ ok: 1 });
    }
    if (m === 'PUT' && path[2] === 'img' && KEY.test(path[3] || '') && path.length === 4) {
      const b = await body();
      if (!b || !imgOk(b.d, 1300000)) return J({ error: 'That image could not be saved.' }, 413);
      await store('online/d/' + id + '/img/' + path[3] + '.json', { d: b.d });
      return J({ ok: 1 });
    }
  }
  return J({ error: 'Not found.' }, 404);
}
