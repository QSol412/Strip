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
  return pl.sub;
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
  let me = null;
  if (bearer) { try { me = await verifyGoogle(bearer, env); } catch (e) { me = null; } }
  const needMe = () => J({ error: 'Please sign in again.' }, 401);
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
        .filter(c => c && ID.test(String(c.id || ''))).map(c => ({ id: String(c.id), name: cut(c.name, 80), pages: Math.max(0, Math.min(999, +c.pages || 0)) }));
      ix[id] = { id, name: cut(b.name, 80), genre: cut(b.genre, 40), syn: cut(b.syn, 600), thumb: imgOk(b.thumb, 300000) ? b.thumb : '', author: cut(b.author, 30), authorUid: me, updated: Date.now(), chapters };
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
