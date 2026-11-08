/* Strip online service: Cloudflare Pages Function. Needs a D1 binding named DB and a variable GOOGLE_CLIENT_ID. */
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}}),
E=(m,s)=>J({error:m},s),ID=/^[\w.-]{1,120}$/,str=(v,n)=>typeof v==='string'?v.slice(0,n):'',
b64u=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
let keys,kt=0,ready;
async function jwk(kid){if(!keys||!keys.some(k=>k.kid===kid)||Date.now()-kt>36e5){keys=(await(await fetch('https://www.googleapis.com/oauth2/v3/certs')).json()).keys;kt=Date.now()}return keys.find(k=>k.kid===kid)}
async function who(rq,env){
 const a=(rq.headers.get('Authorization')||'').slice(7).split('.');if(a.length!==3||!env.GOOGLE_CLIENT_ID)return null;
 try{const td=new TextDecoder(),k=await jwk(JSON.parse(td.decode(b64u(a[0]))).kid);if(!k)return null;
  const ck=await crypto.subtle.importKey('jwk',k,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',ck,b64u(a[2]),new TextEncoder().encode(a[0]+'.'+a[1])))return null;
  const p=JSON.parse(td.decode(b64u(a[1])));
  if(p.aud!==env.GOOGLE_CLIENT_ID||!/^(https:\/\/)?accounts\.google\.com$/.test(p.iss)||p.exp*1000<Date.now())return null;
  return{uid:p.sub,name:p.name||'Creator'}}catch(e){return null}}
export async function onRequest({request:rq,env}){
 try{
  const p=new URL(rq.url).pathname.replace(/^\/api\/?/,'').split('/').filter(Boolean),m=rq.method,db=env.DB;
  if(p[0]==='config')return J({clientId:env.GOOGLE_CLIENT_ID||''});
  if(p[0]==='ads')return J([]);
  if(p[0]!=='stories')return E('Not found',404);
  if(!db)return E('The online service is not set up yet.',503);
  ready=ready||db.batch([db.prepare('CREATE TABLE IF NOT EXISTS stories(id TEXT PRIMARY KEY,uid TEXT,author TEXT,name TEXT,genre TEXT,syn TEXT,thumb TEXT,chapters TEXT,updated INTEGER)'),db.prepare('CREATE TABLE IF NOT EXISTS chunks(sid TEXT,kind TEXT,k TEXT,d TEXT,PRIMARY KEY(sid,kind,k))')]).catch(e=>{ready=0;throw e});
  await ready;
  const[,sid,kind,k]=p;
  if(!sid){if(m!=='GET')return E('Not found',404);
   const r=await db.prepare('SELECT id,uid,author,name,genre,syn,thumb,chapters,updated FROM stories ORDER BY updated DESC LIMIT 300').all();
   return J(r.results.map(o=>({id:o.id,authorUid:o.uid,author:o.author,name:o.name,genre:o.genre,syn:o.syn,thumb:o.thumb,updated:o.updated,chapters:JSON.parse(o.chapters||'[]')})))}
  if(!ID.test(sid))return E('Bad id',400);
  if(m==='GET'&&(kind==='ch'||kind==='img')&&k){
   const r=await db.prepare('SELECT d FROM chunks WHERE sid=? AND kind=? AND k=?').bind(sid,kind,k).first();
   return r?J(kind==='ch'?{j:r.d}:{d:r.d}):E('Not found',404)}
  const u=await who(rq,env);if(!u)return E('Please sign in again.',401);
  const row=await db.prepare('SELECT uid FROM stories WHERE id=?').bind(sid).first();
  if(row&&row.uid!==u.uid)return E('This story belongs to someone else.',403);
  let b={};if(m==='PUT'){try{b=await rq.json()}catch(e){return E('Bad request',400)}}
  if(m==='PUT'&&!kind){
   const ch=(Array.isArray(b.chapters)?b.chapters:[]).slice(0,200).map(c=>({id:str(c.id,120),name:str(c.name,120),pages:+c.pages||0}));
   await db.prepare('INSERT INTO stories(id,uid,author,name,genre,syn,thumb,chapters,updated) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET author=excluded.author,name=excluded.name,genre=excluded.genre,syn=excluded.syn,thumb=excluded.thumb,chapters=excluded.chapters,updated=excluded.updated')
    .bind(sid,u.uid,u.name,str(b.name,120)||'Untitled',str(b.genre,40),str(b.syn,2000),str(b.thumb,4e5),JSON.stringify(ch),Date.now()).run();
   return J({ok:1})}
  if(m==='DELETE'&&!kind){await db.batch([db.prepare('DELETE FROM chunks WHERE sid=?').bind(sid),db.prepare('DELETE FROM stories WHERE id=?').bind(sid)]);return J({ok:1})}
  if(!row)return E('Not found',404);
  if(m==='DELETE'&&kind==='data'){await db.prepare('DELETE FROM chunks WHERE sid=?').bind(sid).run();return J({ok:1})}
  if(m==='PUT'&&(kind==='ch'||kind==='img')&&k&&ID.test(k)){
   const d=kind==='ch'?b.j:b.d;
   if(typeof d!=='string'||d.length>(kind==='ch'?1.5e6:1.1e6)||(kind==='img'&&!d.startsWith('data:image/')))return E('That upload is invalid or too large.',413);
   await db.prepare('INSERT OR REPLACE INTO chunks(sid,kind,k,d) VALUES(?,?,?,?)').bind(sid,kind,k,d).run();return J({ok:1})}
  return E('Not found',404)
 }catch(e){return E('Online service error. Please try again.',500)}
}
