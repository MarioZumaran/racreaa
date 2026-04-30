const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 5,
  connectionTimeoutMillis: 10000,
});

const JWT_SECRET      = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim());

function sha256(d){ return crypto.createHash('sha256').update(JSON.stringify(d)).digest('hex'); }
function sanitize(v,max=500){ return typeof v==='string'?v.slice(0,max).replace(/[<>]/g,''):''; }
function genId(){ return 'AUD-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase(); }

function verifyToken(h) {
  if (!h?.startsWith('Bearer ')) throw new Error('AUTH_MISSING');
  try { return jwt.verify(h.slice(7), JWT_SECRET); }
  catch { throw new Error('AUTH_INVALID'); }
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Client-GPS, X-Request-ID');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method==='OPTIONS') return res.status(204).end();
  if (req.method!=='POST')   return res.status(405).json({success:false,message:'Method Not Allowed'});
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');

  let claims;
  try { claims = verifyToken(req.headers.authorization); }
  catch { return res.status(401).json({success:false,message:'No autorizado.'}); }

  const tenantId   = claims.tenant_id;
  const operatorId = claims.sub;
  const ip         = (req.headers['x-forwarded-for']||'').split(',')[0].trim()||'unknown';
  const ua         = req.headers['user-agent']||'';
  const reqId      = req.headers['x-request-id']||crypto.randomUUID();
  const body       = req.body;

  if (!body||typeof body!=='object') return res.status(400).json({success:false,message:'Payload inválido.'});

  const auditId = genId();
  const serverTs = new Date().toISOString();
  const client  = await pool.connect();

  try {
    await client.query('BEGIN');
    await client.query(`
      INSERT INTO racreaa.audits
        (id,tenant_id,operator_id,establecimiento,auditor_name,audit_date,service_period,
         global_score,conclusion,auditor_firma,chef_firma,
         gps_lat,gps_lng,gps_accuracy,client_ip,user_agent,
         session_token,request_id,client_submitted_at,server_timestamp)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
    `,[auditId,tenantId,operatorId,
       sanitize(body.establecimiento),sanitize(body.auditor),body.fecha||null,sanitize(body.servicio,100),
       body.globalScore||0,sanitize(body.conclusion,2000),sanitize(body.auditorFirma),sanitize(body.chefFirma),
       body.gpsAtSubmission?.lat||null,body.gpsAtSubmission?.lng||null,body.gpsAtSubmission?.accuracy||null,
       ip,ua,sanitize(body.sessionToken,64),reqId,body.submittedAt||null,serverTs]);

    for (const item of (body.items||[]).slice(0,50)) {
      await client.query(`
        INSERT INTO racreaa.audit_items
          (id,audit_id,tenant_id,item_num,nombre,categoria,score,nivel,observaciones,
           crit_presentacion,crit_temperatura,crit_sabor,crit_textura,crit_porcion,server_timestamp)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      `,[`${auditId}-I${item.num}`,auditId,tenantId,item.num,
         sanitize(item.nombre),sanitize(item.categoria),item.score||0,item.nivel||null,
         sanitize(item.observaciones||'',1000),
         item.criterios?.presentacion||0,item.criterios?.temperatura||0,
         item.criterios?.sabor||0,item.criterios?.textura||0,item.criterios?.porcion||0,serverTs]);
    }

    await client.query(`
      INSERT INTO racreaa.audit_logs
        (id,tenant_id,operator_id,audit_id,action,entity_type,entity_id,client_ip,user_agent,request_id,payload_hash,occurred_at)
      VALUES (gen_random_uuid(),$1,$2,$3,'AUDIT_SUBMITTED','audit',$3,$4,$5,$6,$7,NOW())
    `,[tenantId,operatorId,auditId,ip,ua,reqId,sha256({auditId,tenantId,operatorId,serverTs})]);

    await client.query('COMMIT');
    return res.status(200).json({success:true,auditId,timestamp:serverTs,message:'Evaluación registrada correctamente.'});
  } catch(err) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('[submit-audit]',err.message);
    return res.status(500).json({success:false,message:'Error interno.'});
  } finally { client.release(); }
};
