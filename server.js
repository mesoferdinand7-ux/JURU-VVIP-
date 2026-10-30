// JURU VVIP — Node server, member approval system and API-Football proxy
// Render: Web Service | Build: (leave empty) | Start: node server.js
// Environment: API_FOOTBALL_KEY, ADMIN_PASSWORD, ADMIN_WHATSAPP_NUMBER
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,ROOT=__dirname,API_BASE='https://v3.football.api-sports.io';
const DB=process.env.DATA_FILE||path.join(ROOT,'juru-members.json');
const ALLOWED=new Set(['fixtures','predictions','standings','odds','status','fixtures/statistics','fixtures/events','fixtures/lineups','fixtures/players','teams','leagues','countries']);
const sessions=new Map();
function readDB(){try{return JSON.parse(fs.readFileSync(DB,'utf8'))}catch{return {members:[]}}}
function writeDB(db){const tmp=DB+'.tmp';fs.writeFileSync(tmp,JSON.stringify(db,null,2),{mode:0o600});fs.renameSync(tmp,DB)}
function send(res,code,data,type='application/json; charset=utf-8'){res.writeHead(code,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(type.startsWith('application/json')?JSON.stringify(data):data)}
function cookie(req){return (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('juru_session='))?.slice(13)}
function userFor(req){return sessions.get(cookie(req))||null}
function makeSession(res,user){const token=crypto.randomBytes(32).toString('hex');sessions.set(token,user);res.setHeader('Set-Cookie',`juru_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`)}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>20000)reject(new Error('Request too large'))});req.on('end',()=>{try{resolve(JSON.parse(s||'{}'))}catch{reject(new Error('Invalid JSON'))}});req.on('error',reject)})}
function hash(pw,salt=crypto.randomBytes(16).toString('hex')){return new Promise((resolve,reject)=>crypto.scrypt(pw,salt,64,(e,key)=>e?reject(e):resolve({salt,hash:key.toString('hex')})))}
async function verify(pw,stored){const key=await hash(pw,stored.salt);return crypto.timingSafeEqual(Buffer.from(key.hash,'hex'),Buffer.from(stored.hash,'hex'))}
function safeMember(m){return {id:m.id,name:m.name,email:m.email,status:m.status,createdAt:m.createdAt,validationUntil:m.validationUntil||null}}
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
 try{
  if(req.method==='GET'&&url.pathname==='/health')return send(res,200,{ok:true,service:'JURU VVIP'});
  if(req.method==='GET'&&url.pathname==='/api/public-config')return send(res,200,{adminWhatsApp:process.env.ADMIN_WHATSAPP_NUMBER||''});
  if(req.method==='POST'&&url.pathname==='/auth/register'){
   const b=await body(req),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
   if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return send(res,400,{error:'Enter your name, a valid email and a password of at least 8 characters.'});
   const db=readDB();if(db.members.some(m=>m.email===email))return send(res,409,{error:'An account with this email already exists.'});
   const cred=await hash(password),m={id:crypto.randomUUID(),name,email,credential:cred,status:'pending',createdAt:new Date().toISOString(),validationUntil:null};db.members.push(m);writeDB(db);return send(res,201,{ok:true,message:'Registration received. Your account is waiting for admin approval.'});
  }
  if(req.method==='POST'&&url.pathname==='/auth/login'){
   const b=await body(req),email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||''),m=readDB().members.find(x=>x.email===email);
   if(!m||!await verify(pw,m.credential))return send(res,401,{error:'Incorrect email or password.'});
   if(m.status!=='approved')return send(res,403,{error:m.status==='pending'?'Your membership is awaiting admin approval.':'Your membership is not active.'});
   if(!m.validationUntil||Date.now()>Date.parse(m.validationUntil))return send(res,403,{error:'Your membership has expired. Contact the admin to renew.'});
   makeSession(res,{role:'member',id:m.id});return send(res,200,{ok:true,member:safeMember(m)});
  }
  if(req.method==='POST'&&url.pathname==='/admin/login'){
   const b=await body(req);if(!process.env.ADMIN_PASSWORD)return send(res,503,{error:'Set ADMIN_PASSWORD in Render Environment first.'});
   const a=String(b.password||''),expected=process.env.ADMIN_PASSWORD;
   const aa=Buffer.from(a),ee=Buffer.from(expected);if(aa.length!==ee.length||!crypto.timingSafeEqual(aa,ee))return send(res,401,{error:'Incorrect admin password.'});
   makeSession(res,{role:'admin'});return send(res,200,{ok:true});
  }
  if(req.method==='GET'&&url.pathname==='/admin/members'){
   if(userFor(req)?.role!=='admin')return send(res,401,{error:'Admin login required.'});return send(res,200,{members:readDB().members.map(safeMember)});
  }
  if(req.method==='POST'&&url.pathname==='/admin/member-action'){
   if(userFor(req)?.role!=='admin')return send(res,401,{error:'Admin login required.'});const b=await body(req),db=readDB(),m=db.members.find(x=>x.id===b.id);if(!m)return send(res,404,{error:'Member not found.'});
   if(b.action==='approve'){const days=Number(b.days);if(!Number.isInteger(days)||days<1||days>365)return send(res,400,{error:'Choose a validation period from 1 to 365 days.'});m.status='approved';m.validationUntil=new Date(Date.now()+days*86400000).toISOString()}
   else if(b.action==='reject'){m.status='rejected';m.validationUntil=null}else if(b.action==='revoke'){m.status='suspended'}else return send(res,400,{error:'Unknown action'});writeDB(db);return send(res,200,{ok:true,member:safeMember(m)});
  }
  if(req.method==='POST'&&url.pathname==='/auth/logout'){const token=cookie(req);if(token)sessions.delete(token);res.setHeader('Set-Cookie','juru_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return send(res,200,{ok:true});}
  if(url.pathname.startsWith('/api/')){const endpoint=decodeURIComponent(url.pathname.slice(5));if(!ALLOWED.has(endpoint))return send(res,404,{error:'API endpoint not allowed'});const key=process.env.API_FOOTBALL_KEY;if(!key)return send(res,503,{error:'API key not configured. Add API_FOOTBALL_KEY in Render Environment.'});const target=new URL(API_BASE+'/'+endpoint);for(const[k,v]of url.searchParams)target.searchParams.set(k,v);const upstream=await fetch(target,{headers:{'x-apisports-key':key},signal:AbortSignal.timeout(18000)});const data=await upstream.text();res.writeHead(upstream.status,{'Content-Type':upstream.headers.get('content-type')||'application/json','Cache-Control':'no-store'});return res.end(data)}
  let p=decodeURIComponent(url.pathname);if(p==='/')p='/index.html';const file=path.resolve(ROOT,'.'+p);if(!file.startsWith(ROOT+path.sep)&&file!==path.join(ROOT,'index.html'))return send(res,403,{error:'Forbidden'});const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml'};fs.readFile(file,(e,d)=>e?send(res,404,{error:'File not found'}):send(res,200,d,types[path.extname(file)]||'application/octet-stream'));
 }catch(e){send(res,400,{error:e.message||'Request failed'})}
});
server.listen(PORT,'0.0.0.0',()=>console.log(`JURU VVIP listening on ${PORT}`));
