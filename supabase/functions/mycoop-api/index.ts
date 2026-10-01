const SITE='https://checkfile2568-ops.github.io';
const ITERATIONS=600000;
const CORS={'Access-Control-Allow-Origin':SITE,'Access-Control-Allow-Headers':'content-type,x-mycoop-token','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS','Vary':'Origin','Cache-Control':'no-store','Content-Type':'application/json'};
const hex=(b)=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
const b64=(b)=>btoa(String.fromCharCode(...new Uint8Array(b)));
const un64=(s)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function digest(s){return hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))}
async function verifier(password,salt){const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',salt:un64(salt),iterations:ITERATIONS,hash:'SHA-256'},key,256))}
function equal(a,b){let d=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0}
function reply(body,status=200){return new Response(JSON.stringify(body),{status,headers:CORS})}
async function db(path,method='GET',body){const secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');const r=await fetch(Deno.env.get('SUPABASE_URL')+'/rest/v1/'+path,{method,headers:{apikey:secret,Authorization:'Bearer '+secret,'Content-Type':'application/json',Prefer:'return=representation'},body:body===undefined?undefined:JSON.stringify(body)});if(!r.ok)throw Error('database request failed');const t=await r.text();return t?JSON.parse(t):null}
function validVault(v){try{return v&&v.format==='mycoop-vault'&&v.version===1&&v.iterations===ITERATIONS&&typeof v.cipher==='string'&&v.cipher.length<=6500000&&un64(v.cipher).length>=16&&un64(v.salt).length===16&&un64(v.iv).length===12}catch{return false}}
async function requestBody(req){const limit=8000000;const reader=req.body?.getReader();if(!reader)return {};let total=0;const chunks=[];while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>limit){await reader.cancel();throw Error('request too large')}chunks.push(value)}const bytes=new Uint8Array(total);let pos=0;for(const c of chunks){bytes.set(c,pos);pos+=c.length}return JSON.parse(new TextDecoder().decode(bytes))}
async function allowLogin(req){const stamp=Math.floor(Date.now()/900000),ip=req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()||'unknown',expires=new Date((stamp+2)*900000).toISOString();const buckets=[['all:'+stamp,120],['ip:'+await digest(ip)+':'+stamp,12]];for(const [bucket,limit] of buckets){if(!await db('rpc/mycoop_take_attempt','POST',{p_bucket:bucket,p_limit:limit,p_expires:expires}))return false}return true}
async function handler(req){
 const origin=req.headers.get('Origin');if(origin&&origin!==SITE)return reply({error:'Origin not allowed'},403);
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:CORS});
 const action=new URL(req.url).pathname.split('/').filter(Boolean).at(-1);
 try{
  if(action==='health'&&req.method==='GET')return reply({ok:true});
  if(action==='login'&&req.method==='POST'){
   if(!await allowLogin(req))return reply({error:'ลองรหัสหลายครั้งเกินไป กรุณารอ 15 นาที'},429);
   const body=await requestBody(req);if(typeof body.password!=='string'||!body.password)return reply({error:'กรุณากรอกรหัส'},400);
   const row=(await db('mycoop_vault?id=eq.1&select=*'))[0];if(!row)return reply({error:'ระบบยังไม่พร้อม'},503);
   const hash=await verifier(body.password,row.auth_salt);if(!equal(hash,row.auth_hash))return reply({error:'รหัสไม่ถูกต้อง'},401);
   const token=hex(crypto.getRandomValues(new Uint8Array(32))),tokenHash=await digest(token),expires=new Date(Date.now()+12*3600000).toISOString();
   await db('mycoop_sessions','POST',{token_hash:tokenHash,auth_version:row.auth_version,expires_at:expires});
   await db('mycoop_sessions?expires_at=lt.'+encodeURIComponent(new Date().toISOString()),'DELETE');
   await db('mycoop_rate_limits?expires_at=lt.'+encodeURIComponent(new Date().toISOString()),'DELETE');
   return reply({token,revision:row.revision,vault:row.payload,updatedAt:row.updated_at});
  }
  const token=req.headers.get('x-mycoop-token');if(!token||!/^[a-f0-9]{64}$/.test(token))return reply({error:'กรุณาเข้าสู่ระบบ'},401);
  const tokenHash=await digest(token),session=(await db('mycoop_sessions?token_hash=eq.'+tokenHash+'&expires_at=gt.'+encodeURIComponent(new Date().toISOString())+'&select=auth_version'))[0];if(!session)return reply({error:'หมดเวลาเข้าใช้งาน กรุณาใส่รหัสอีกครั้ง'},401);
  const row=(await db('mycoop_vault?id=eq.1&select=*'))[0];if(!row||row.auth_version!==session.auth_version)return reply({error:'มีการเปลี่ยนรหัส กรุณาเข้าใช้งานใหม่'},401);
  if(action==='logout'&&req.method==='POST'){await db('mycoop_sessions?token_hash=eq.'+tokenHash,'DELETE');return reply({ok:true})}
  if(action==='data'&&req.method==='GET')return reply({vault:row.payload,revision:row.revision,updatedAt:row.updated_at});
  if((action==='data'&&req.method==='PUT')||(action==='password'&&req.method==='PUT')){
   const body=await requestBody(req);if(!validVault(body.vault)||!Number.isSafeInteger(body.revision))return reply({error:'ข้อมูลไม่ถูกต้อง'},400);
   if(body.revision!==row.revision)return reply({error:'มีข้อมูลใหม่จากอีกเครื่อง กรุณาดึงข้อมูลล่าสุดก่อนบันทึก',code:'conflict'},409);
   const update={payload:body.vault,revision:row.revision+1,updated_at:new Date().toISOString()};
   if(action==='password'){
    if(typeof body.newPassword!=='string'||!body.newPassword)return reply({error:'กรุณากรอกรหัสใหม่'},400);
    // Ensure the new passphrase can decrypt the accompanying vault before rotating authentication.
    const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(body.newPassword),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:un64(body.vault.salt),iterations:ITERATIONS,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
    try{await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(body.vault.iv)},key,un64(body.vault.cipher))}catch{return reply({error:'รหัสใหม่กับข้อมูลเข้ารหัสไม่ตรงกัน'},400)}
    update.auth_salt=b64(crypto.getRandomValues(new Uint8Array(16)));update.auth_hash=await verifier(body.newPassword,update.auth_salt);update.auth_version=row.auth_version+1;
   }
   const changed=await db('mycoop_vault?id=eq.1&revision=eq.'+row.revision+'&auth_version=eq.'+row.auth_version,'PATCH',update);
   if(!changed?.length)return reply({error:'มีข้อมูลเปลี่ยนแปลงจากอีกเครื่อง กรุณาดึงข้อมูลล่าสุด',code:'conflict'},409);
   if(action==='password'){await db('mycoop_sessions?token_hash=eq.'+tokenHash,'PATCH',{auth_version:update.auth_version})}
   return reply({revision:changed[0].revision,updatedAt:changed[0].updated_at});
  }
  return reply({error:'Not found'},404);
 }catch(e){return reply({error:e.message==='request too large'?'ข้อมูลใหญ่เกินขนาดที่กำหนด':'ติดต่อฐานข้อมูลไม่สำเร็จ กรุณาลองใหม่'},e.message==='request too large'?413:500)}
}
Deno.serve(handler);
