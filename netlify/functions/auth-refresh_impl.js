const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');

const pool = new Pool({ connectionString:process.env.DATABASE_URL, ssl:{rejectUnauthorized:true}, max:5 });
const JWT_SECRET      = process.env.JWT_SECRET;
const JWT_EXPIRY      = process.env.JWT_EXPIRY||'15m';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim());

function parseCookies(h) {
  if(!h) return {};
  return Object.fromEntries(h.split(';').map(c=>{const[k,...v]=c.trim().split('=');return[k.trim(),v.join('=').trim()];}));
}
function rtCookie(raw) {
  return [`racreaa_rt=${raw}`,`Max-Age=${60*60*24*7}`,`Path=/api/auth`,`HttpOnly`,`Secure`,`SameSite=Strict`].join('; ');
}
function clearCookie() { return `racreaa_rt=; Max-Age=0; Path=/api/auth; HttpOnly; Secure; SameSite=Strict`; }
function issueJWT(op, tenant) {
  const jti=crypto.randomUUID();
  return { token: jwt.sign({sub:op.id,jti,tenant_id:tenant.id,tenant_slug:tenant.slug,role:op.role,full_name:op.full_name,email:op.email},
    JWT_SECRET,{algorithm:'HS256',expiresIn:JWT_EXPIRY,issuer:'racreaa.dmzkitchensupport.com',audience:tenant.slug}), jti };
}
function sha256(d) { return crypto.createHash('sha256').update(JSON.stringify(d)).digest('hex'); }

module.exports = async function handler(req,res) {
  const origin=req.headers.origin||'';
  if(ALLOWED_ORIGINS.includes(origin)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');res.setHeader('Access-Control-Allow-Credentials','true');res.setHeader('Vary','Origin');}
  if(req.method==='OPTIONS') return res.status(204).end();
  if(req.method!=='POST')    return res.status(405).end();
  res.setHeader('Cache-Control','no-store');

  const ip=((req.headers['x-forwarded-for']||'').split(',')[0].trim())||'unknown';
  const ua=req.headers['user-agent']||'';
  const cookies=parseCookies(req.headers.cookie);
  const refreshRaw=cookies['racreaa_rt'];
  if(!refreshRaw){res.setHeader('Set-Cookie',clearCookie());return res.status(401).json({success:false,message:'Sin sesión activa.'});}

  const hash=crypto.createHash('sha256').update(refreshRaw).digest('hex');
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const rtRes=await client.query(`
      SELECT rt.*,op.id as op_id,op.full_name,op.email,op.role,op.is_active as op_active,
        t.id as t_id,t.slug,t.name as t_name,t.brand_name,t.is_active as t_active,t.plan
      FROM racreaa.refresh_tokens rt
      JOIN racreaa.operators op ON op.id=rt.operator_id
      JOIN racreaa.tenants t ON t.id=rt.tenant_id
      WHERE rt.token_hash=$1 LIMIT 1 FOR UPDATE`,[hash]);
    const rt=rtRes.rows[0];
    if(!rt){await client.query('ROLLBACK');res.setHeader('Set-Cookie',clearCookie());return res.status(401).json({success:false,message:'Sesión inválida.'});}
    if(rt.revoked_at){
      await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at=NOW(),reuse_detected=TRUE WHERE operator_id=$1 AND revoked_at IS NULL`,[rt.operator_id]);
      await client.query('COMMIT');res.setHeader('Set-Cookie',clearCookie());
      return res.status(401).json({success:false,message:'Sesión comprometida. Inicie sesión nuevamente.'});
    }
    if(new Date()>new Date(rt.expires_at)){
      await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at=NOW() WHERE id=$1`,[rt.id]);
      await client.query('COMMIT');res.setHeader('Set-Cookie',clearCookie());
      return res.status(401).json({success:false,message:'Sesión expirada.'});
    }
    if(!rt.op_active||!rt.t_active){
      await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at=NOW() WHERE id=$1`,[rt.id]);
      await client.query('COMMIT');res.setHeader('Set-Cookie',clearCookie());
      return res.status(401).json({success:false,message:'Cuenta inactiva.'});
    }
    await client.query(`UPDATE racreaa.refresh_tokens SET revoked_at=NOW() WHERE id=$1`,[rt.id]);
    const op={id:rt.op_id,full_name:rt.full_name,email:rt.email,role:rt.role};
    const tenant={id:rt.t_id,slug:rt.slug,name:rt.t_name,brand_name:rt.brand_name,plan:rt.plan};
    const {token,jti}=issueJWT(op,tenant);
    const newRaw=crypto.randomBytes(64).toString('hex');
    const newHash=crypto.createHash('sha256').update(newRaw).digest('hex');
    await client.query(`INSERT INTO racreaa.refresh_tokens (id,operator_id,tenant_id,token_hash,jti,client_ip,user_agent,expires_at,created_at) VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,NOW())`,
      [rt.operator_id,rt.tenant_id,newHash,jti,ip,ua,new Date(Date.now()+7*24*60*60*1000)]);
    await client.query(`INSERT INTO racreaa.audit_logs (id,tenant_id,operator_id,action,entity_type,entity_id,client_ip,user_agent,payload_hash,occurred_at) VALUES (gen_random_uuid(),$1,$2,'TOKEN_REFRESHED','auth',$2,$3,$4,$5,NOW())`,
      [rt.tenant_id,rt.operator_id,ip,ua,sha256({jti,op:rt.operator_id})]);
    await client.query('COMMIT');
    res.setHeader('Set-Cookie',rtCookie(newRaw));
    return res.status(200).json({success:true,access_token:token,token_type:'Bearer',expires_in:JWT_EXPIRY,operator:op,tenant});
  } catch(err) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('[RACREAA/refresh]',err.message);
    return res.status(500).json({success:false,message:'Error interno.'});
  } finally { client.release(); }
};
