/**
 * /api/auth/login.js — RACREAA Auth (CommonJS)
 */
const { Pool }  = require('pg');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

const JWT_SECRET      = process.env.JWT_SECRET;
const JWT_EXPIRY      = process.env.JWT_EXPIRY || '15m';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
const REDIS_URL       = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN_R   = process.env.UPSTASH_REDIS_REST_TOKEN;
const HAS_REDIS       = !!(REDIS_URL && REDIS_TOKEN_R);

async function checkRateLimit(ip) {
  if (!HAS_REDIS) return { allowed: true, remaining: 5 };
  try {
    const headers = { Authorization: `Bearer ${REDIS_TOKEN_R}` };
    const block   = await fetch(`${REDIS_URL}/get/racreaa:login_block:${ip}`, { headers });
    if ((await block.json()).result) return { allowed: false, retryAfter: 1800 };
    const cnt     = await fetch(`${REDIS_URL}/get/racreaa:login_fail:${ip}`, { headers });
    const count   = parseInt((await cnt.json()).result || '0', 10);
    return { allowed: true, remaining: Math.max(0, 5 - count) };
  } catch { return { allowed: true, remaining: 5 }; }
}

async function recordFail(ip) {
  if (!HAS_REDIS) return;
  try {
    const headers = { Authorization: `Bearer ${REDIS_TOKEN_R}`, 'Content-Type': 'application/json' };
    await fetch(`${REDIS_URL}/pipeline`, { method:'POST', headers,
      body: JSON.stringify([['INCR',`racreaa:login_fail:${ip}`],['EXPIRE',`racreaa:login_fail:${ip}`,900]]) });
    const cnt   = await fetch(`${REDIS_URL}/get/racreaa:login_fail:${ip}`, { headers });
    const count = parseInt((await cnt.json()).result||'0',10);
    if (count >= 5) await fetch(`${REDIS_URL}/set/racreaa:login_block:${ip}/1/ex/1800`, { headers });
  } catch {}
}

async function clearFails(ip) {
  if (!HAS_REDIS) return;
  try { await fetch(`${REDIS_URL}/del/racreaa:login_fail:${ip}`, { headers:{ Authorization:`Bearer ${REDIS_TOKEN_R}` } }); } catch {}
}

function sanitize(v, max=255) { return typeof v==='string' ? v.toLowerCase().trim().slice(0,max) : ''; }
function slugify(v) { return typeof v==='string' ? v.toLowerCase().trim().replace(/[^a-z0-9-]/g,'').slice(0,64) : ''; }

function issueJWT(operator, tenant) {
  const jti = crypto.randomUUID();
  return {
    token: jwt.sign({ sub:operator.id, jti, tenant_id:tenant.id, tenant_slug:tenant.slug,
      role:operator.role, full_name:operator.full_name, email:operator.email },
      JWT_SECRET, { algorithm:'HS256', expiresIn:JWT_EXPIRY,
        issuer:'racreaa.dmzkitchensupport.com', audience:tenant.slug }),
    jti,
  };
}

function rtCookie(raw) {
  return [`racreaa_rt=${raw}`,`Max-Age=${60*60*24*7}`,`Path=/api/auth`,`HttpOnly`,`Secure`,`SameSite=Strict`].join('; ');
}

function sha256(data) { return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex'); }

module.exports = async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Request-ID');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary','Origin');
  }
  if (req.method==='OPTIONS') return res.status(204).end();
  if (req.method!=='POST')   return res.status(405).json({ success:false, message:'Method Not Allowed' });

  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Strict-Transport-Security','max-age=63072000; includeSubDomains; preload');
  res.setHeader('Cache-Control','no-store');

  const ip        = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || 'unknown';
  const ua        = req.headers['user-agent'] || '';
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();

  const rate = await checkRateLimit(ip);
  if (!rate.allowed) return res.status(429).json({ success:false, message:'Demasiados intentos. Intente en 30 minutos.', retryAfter:1800 });

  const { email:rawEmail, password, tenant_slug:rawSlug } = req.body || {};
  const email      = sanitize(rawEmail);
  const tenantSlug = slugify(rawSlug);

  if (!email||!password||!tenantSlug)
    return res.status(400).json({ success:false, message:'Los campos email, password y tenant_slug son obligatorios.' });
  if (typeof password!=='string'||password.length<8||password.length>128)
    return res.status(400).json({ success:false, message:'Credenciales inválidas.' });

  const DUMMY = '$2a$12$dummyhashXXXXXXXXXXXXXuGQp5MqnZwPzNM4HHp7HlXRvG1kDke';
  const client = await pool.connect();
  try {
    const tenantRes = await client.query(
      `SELECT id,slug,name,brand_name,is_active,plan FROM racreaa.tenants WHERE slug=$1 LIMIT 1`,[tenantSlug]);
    const tenant = tenantRes.rows[0];
    if (!tenant||!tenant.is_active) {
      await bcrypt.compare(password, DUMMY);
      await recordFail(ip);
      return res.status(401).json({ success:false, message:'Credenciales incorrectas.' });
    }

    const opRes = await client.query(
      `SELECT id,tenant_id,email,full_name,role,password_hash,is_active FROM racreaa.operators WHERE email=$1 AND tenant_id=$2 LIMIT 1`,
      [email, tenant.id]);
    const op = opRes.rows[0];
    if (!op) {
      await bcrypt.compare(password, DUMMY);
      await recordFail(ip);
      return res.status(401).json({ success:false, message:'Credenciales incorrectas.' });
    }
    if (!op.is_active) {
      await bcrypt.compare(password, DUMMY);
      return res.status(401).json({ success:false, message:'Cuenta inactiva.' });
    }

    const valid = await bcrypt.compare(password, op.password_hash);
    if (!valid) {
      await recordFail(ip);
      return res.status(401).json({ success:false, message:'Credenciales incorrectas.', remaining: Math.max(0,(rate.remaining||5)-1) });
    }

    const { token, jti }       = issueJWT(op, tenant);
    const raw                  = crypto.randomBytes(64).toString('hex');
    const hash                 = crypto.createHash('sha256').update(raw).digest('hex');
    const exp                  = new Date(Date.now()+7*24*60*60*1000);

    await client.query('BEGIN');
    await client.query(
      `INSERT INTO racreaa.refresh_tokens (id,operator_id,tenant_id,token_hash,jti,client_ip,user_agent,expires_at,created_at)
       VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,NOW())`,
      [op.id,tenant.id,hash,jti,ip,ua,exp]);
    await client.query(`UPDATE racreaa.operators SET last_login_at=NOW() WHERE id=$1`,[op.id]);
    await client.query(
      `INSERT INTO racreaa.audit_logs (id,tenant_id,operator_id,action,entity_type,entity_id,client_ip,user_agent,request_id,payload_hash,occurred_at)
       VALUES (gen_random_uuid(),$1,$2,'LOGIN_SUCCESS','auth',$2,$3,$4,$5,$6,NOW())`,
      [tenant.id,op.id,ip,ua,requestId,sha256({jti,op:op.id,tenant:tenant.id,ip})]);
    await client.query('COMMIT');
    await clearFails(ip);

    res.setHeader('Set-Cookie', rtCookie(raw));
    return res.status(200).json({
      success:true, access_token:token, token_type:'Bearer', expires_in:JWT_EXPIRY,
      operator:{ id:op.id, full_name:op.full_name, email:op.email, role:op.role },
      tenant:{ id:tenant.id, slug:tenant.slug, name:tenant.name, brand_name:tenant.brand_name, plan:tenant.plan },
    });

  } catch(err) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('[RACREAA/login]', err.message);
    return res.status(500).json({ success:false, message:'Error interno.' });
  } finally {
    client.release();
  }
};
