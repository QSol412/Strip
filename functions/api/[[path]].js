// Strip votes + comments: shared, public storage in R2.
// Cloudflare Pages Function, served at /api/social/*
//
// Uses the SAME bindings you already set up for sync (Pages project, Settings):
//   Bindings   -> R2 bucket,  variable name: SYNC_BUCKET
//   Variables  -> GOOGLE_CLIENT_ID
// (No new secrets needed.) Reading is open to everyone; voting, commenting and deleting
// your own comment need a Google sign-in (Authorization: Bearer <Google credential>).
//
// Routes
//   GET    tally                      -> {"s_<storyId>": {up,dn,mine}, ...}   (all story votes, one call)
//   PUT    vote   {id,v,story?}       -> v is 1, -1 or 0. id is "s_<storyId>" or "c_<commentId>" (comments also send story)
//   GET    comments/:story            -> {comments:[{id,uid,name,text,t,up,dn,mine}]}  newest first
//   POST   comments/:story {text,name}-> adds a comment
//   DELETE comments/:story/:cid       -> removes your own comment

const TE = new TextEncoder(), TD = new TextDecoder();
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const ID = /^[\w-]{1,64}$/, CID = /^[\w-]{1,24}$/;
const MAX_COMMENTS = 300, MAX_TEXT = 500;

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

export async function onRequest({ request, env }) {
  if (!env.SYNC_BUCKET || !env.GOOGLE_CLIENT_ID) return J({ error: 'Votes and comments are not set up on the server yet.' }, 503);
  const R = env.SYNC_BUCKET, url = new URL(request.url), m = request.method;
  const path = url.pathname.replace(/^\/api\/social\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  const bearer = (request.headers.get('Authorization') || '').replace(/^Bearer /, '');
  let me = null;
  if (bearer) { try { me = await verifyGoogle(bearer, env); } catch (e) { me = null; } }
  const needMe = () => J({ error: 'Please sign in again.' }, 401);
  const none = { up: 0, dn: 0, mine: 0 };

  if (m === 'GET' && path[0] === 'tally') return J(await scan(R, 'social/v/', me));

  if (m === 'PUT' && path[0] === 'vote') {
    if (!me) return needMe();
    let b; try { b = await request.json(); } catch (e) { return J({ error: 'Bad request.' }, 400); }
    const id = String(b.id || ''), v = +b.v;
    if (![1, -1, 0].includes(v)) return J({ error: 'Bad vote.' }, 400);
    let key, pre, pick;
    if (/^s_[\w-]{1,62}$/.test(id)) { pre = 'social/v/' + id + '/'; key = pre + me; pick = ''; }
    else if (/^c_[\w-]{1,22}$/.test(id) && ID.test(b.story || '')) { pre = 'social/cv/' + b.story + '/' + id.slice(2) + '/'; key = pre + me; pick = ''; }
    else return J({ error: 'Bad vote.' }, 400);
    if (v) await R.put(key, '', { customMetadata: { v: String(v) } }); else await R.delete(key);
    return J((await scan(R, pre, me))[pick] || none);
  }

  if (path[0] === 'comments' && ID.test(path[1] || '')) {
    const story = path[1], ck = 'social/c/' + story + '.json';
    const load = async () => { const o = await R.get(ck); try { return o ? await o.json() : []; } catch (e) { return []; } };
    if (m === 'GET' && path.length === 2) {
      const all = await load(), votes = await scan(R, 'social/cv/' + story + '/', me);
      return J({ comments: all.slice(-100).reverse().map(c => ({ ...c, ...(votes[c.id] || none) })) });
    }
    if (m === 'POST' && path.length === 2) {
      if (!me) return needMe();
      let b; try { b = await request.json(); } catch (e) { return J({ error: 'Bad request.' }, 400); }
      const text = String(b.text || '').trim().slice(0, MAX_TEXT), name = String(b.name || '').trim().slice(0, 30);
      if (!text) return J({ error: 'Write something first.' }, 400);
      const all = await load();
      const last = all.filter(c => c.uid === me).pop();
      if (last && Date.now() - last.t < 3000) return J({ error: 'Slow down a little.' }, 429);
      const c = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), uid: me, name, text, t: Date.now() };
      all.push(c);
      await R.put(ck, JSON.stringify(all.slice(-MAX_COMMENTS)), { httpMetadata: { contentType: 'application/json' } });
      return J({ ok: 1, id: c.id });
    }
    if (m === 'DELETE' && path.length === 3 && CID.test(path[2])) {
      if (!me) return needMe();
      const all = await load(), keep = all.filter(c => !(c.id === path[2] && c.uid === me));
      if (keep.length === all.length) return J({ error: 'You can only delete your own comments.' }, 403);
      await R.put(ck, JSON.stringify(keep), { httpMetadata: { contentType: 'application/json' } });
      const l = await R.list({ prefix: 'social/cv/' + story + '/' + path[2] + '/' });
      if (l.objects.length) await R.delete(l.objects.map(o => o.key));
      return J({ ok: 1 });
    }
  }
  return J({ error: 'Not found.' }, 404);
}
