const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');

const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:true},max:5});
const JWT_SECRET=process.env.JWT_SECRET;
const ALLOWED_ORIGINS=(process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim());

function parseCookies(h){if(!h)return{};return Object.fromEntries(h.split(';').map(c=>{const[k,...v]=c.trim().split('=');return[k.trim(),v.join('=').trim()];}));}
function sha256(d){return crypto.createHash('sha256').update(JSON.stringify(d)).digest('hex');}

module.exports = async function handler(req,res){
  const origin=req.headers.origin||'';
  if(ALLOWED_ORIGINS.includes(origin)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');res.setHeader('Access-Control-Allow-Credentials','true');res.setHeader('Vary','Origin');}
  if(req.method==='OPTIONS') return res.status(204).end();
  if(req.method!=='POST')    return res.status(405).end();
  res.setHeader('Cache-Control','no-store');

  const ip=((req.headers['x-forwarded-for']||'').split(',')[0])||'unknown';
  const ua=req.headers['user-agent']||'';
  const allDevices=req.body?.all_devices===true;
  const clear=`racreaa_rt=; Max-Age=0; Path=/api/auth; HttpOnly; Secure; SameSite=Strict`;

  let operatorId=null,tenantId=null;
  const auth=req.headers.authorization;
  if(auth?.startsWith('Bearer ')){try{const d=jwt.verify(auth.slice(7),JWT_SECRET,{algorithms:['HS256']});operatorId=d.sub;tenantId=d.tenant_id;}catch{}}

  const cookies=parseCookies(req.headers.cookie);
  const raw=cookies['racreaa_rt'];
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    if(raw){
      const hash=crypto.createHash('sha256').update(raw).digest('hex');
      const r=await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL RETURNING operator_id,tenant_id`,[hash]);
      if(r.rows[0]){operatorId=operatorId||r.rows[0].operator_id;tenantId=tenantId||r.rows[0].tenant_id;}
    }
    if(allDevices&&operatorId) await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at=NOW() WHERE operator_id=$1 AND revoked_at IS NULL`,[operatorId]);
    if(operatorId) await client.query(`INSERT INTO racreaa.audit_logs (id,tenant_id,operator_id,action,entity_type,entity_id,client_ip,user_agent,payload_hash,occurred_at) VALUES (gen_random_uuid(),$1,$2,$3,'auth',$2,$4,$5,$6,NOW())`,
      [tenantId,operatorId,allDevices?'LOGOUT_ALL_DEVICES':'LOGOUT',ip,ua,sha256({op:operatorId,allDevices,ip})]);
    await client.query('COMMIT');
    res.setHeader('Set-Cookie',clear);
    return res.status(200).json({success:true,message:'Sesión cerrada.'});
  } catch(err){
    await client.query('ROLLBACK').catch(()=>{});
    res.setHeader('Set-Cookie',clear);
    return res.status(500).json({success:false,message:'Error interno.'});
  } finally { client.release(); }
};
