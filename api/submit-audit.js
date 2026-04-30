/**
 * /api/submit-audit.js — RACREAA (CommonJS)
 */
const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 5,
});

const JWT_SECRET      = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim());

function verifyToken(authHeader) {
  if (!authHeader?.startsWith('Bearer ')) throw new Error('AUTH_MISSING');
  const token = authHeader.slice(7);
  try { return jwt.verify(token, JWT_SECRET); }
  catch {
    if (process.env.NODE_ENV==='development') return { sub:token, tenant_id:'demo', role:'auditor' };
    throw new Error('AUTH_INVALID');
  }
}

function sha256(data) { return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex'); }

function genAuditId() {
  return 'AUD-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
}

function sanitize(v, max=500) { return typeof v==='string' ? v.slice(0,max).replace(/[<>]/g,'') : ''; }

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',origin);
    res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Client-GPS, X-Request-ID');
    res.setHeader('Vary','Origin');
  }
  if (req.method==='OPTIONS') return res.status(204).end();
  if (req.method!=='POST')   return res.status(405).json({ success:false, message:'Method Not Allowed' });

  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Strict-Transport-Security','max-age=63072000; includeSubDomains; preload');
  res.setHeader('Cache-Control','no-store');

  let tokenClaims;
  try { tokenClaims = verifyToken(req.headers.authorization); }
  catch { return res.status(401).json({ success:false, message:'No autorizado.' }); }

  const tenantId   = tokenClaims.tenant_id || 'demo';
  const operatorId = tokenClaims.sub;
  const clientIP   = (req.headers['x-forwarded-for']||'').split(',')[0].trim()||'unknown';
  const ua         = req.headers['user-agent']||'';
  const requestId  = req.headers['x-request-id']||crypto.randomUUID();
  const clientGPS  = req.headers['x-client-gps']||null;

  const body = req.body;
  if (!body||typeof body!=='object') return res.status(400).json({ success:false, message:'Payload inválido.' });

  const auditId        = genAuditId();
  const serverTimestamp = new Date().toISOString();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      INSERT INTO racreaa.audits (id,tenant_id,operator_id,establecimiento,auditor_name,audit_date,
        service_period,global_score,conclusion,auditor_firma,chef_firma,signature_image,
        gps_lat,gps_lng,gps_accuracy,client_gps_header,client_ip,user_agent,
        session_token,request_id,client_submitted_at,server_timestamp)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
    `,[
      auditId, tenantId, operatorId,
      sanitize(body.establecimiento), sanitize(body.auditor), body.fecha||null,
      sanitize(body.servicio,100), body.globalScore||0, sanitize(body.conclusion,2000),
      sanitize(body.auditorFirma), sanitize(body.chefFirma),
      typeof body.signatureImage==='string' ? body.signatureImage : null,
      body.gpsAtSubmission?.lat||null, body.gpsAtSubmission?.lng||null, body.gpsAtSubmission?.accuracy||null,
      clientGPS, clientIP, ua,
      sanitize(body.sessionToken,64), requestId,
      body.submittedAt||null, serverTimestamp
    ]);

    for (const item of (body.items||[]).slice(0,50)) {
      const itemId = `${auditId}-ITEM-${item.num}`;
      await client.query(`
        INSERT INTO racreaa.audit_items (id,audit_id,tenant_id,item_num,nombre,categoria,score,nivel,
          observaciones,crit_presentacion,crit_temperatura,crit_sabor,crit_textura,crit_porcion,server_timestamp)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      `,[itemId, auditId, tenantId, item.num, sanitize(item.nombre), sanitize(item.categoria),
         item.score||0, item.nivel||null, sanitize(item.observaciones||'',1000),
         item.criterios?.presentacion||0, item.criterios?.temperatura||0,
         item.criterios?.sabor||0, item.criterios?.textura||0, item.criterios?.porcion||0,
         serverTimestamp]);
    }

    await client.query(`
      INSERT INTO racreaa.audit_logs (id,tenant_id,operator_id,audit_id,action,entity_type,entity_id,
        client_ip,user_agent,request_id,gps_lat,gps_lng,payload_hash,occurred_at)
      VALUES (gen_random_uuid(),$1,$2,$3,'AUDIT_SUBMITTED','audit',$3,$4,$5,$6,$7,$8,$9,NOW())
    `,[tenantId, operatorId, auditId, clientIP, ua, requestId,
       body.gpsAtSubmission?.lat||null, body.gpsAtSubmission?.lng||null,
       sha256({ auditId, tenantId, operatorId, serverTimestamp, score:body.globalScore })]);

    await client.query('COMMIT');

    return res.status(200).json({ success:true, auditId, timestamp:serverTimestamp, message:'Evaluación registrada.' });

  } catch(err) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('[RACREAA/submit-audit]', err.message);
    return res.status(500).json({ success:false, message:'Error interno.' });
  } finally {
    client.release();
  }
};
