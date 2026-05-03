/**
 * submit-audit_impl.js — DMZ Audit
 * Guarda: audits + audit_items + audit_evidence (fotos) + audit_logs
 */
const { Pool }   = require('pg');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const { Resend } = require('resend');

const pool   = new Pool({ connectionString: process.env.DATABASE_URL, ssl:{ rejectUnauthorized:true }, max:5 });
const resend = new Resend(process.env.RESEND_API_KEY);

const JWT_SECRET   = process.env.JWT_SECRET;
const REPORT_EMAIL = process.env.AUDIT_REPORT_EMAIL || 'mario@delamorazumaran.com';

const ALLOWED_ORIGINS = [
  ...(process.env.ALLOWED_ORIGINS||'').split(',').map(s=>s.trim()),
  'https://dmzkitchensupport.github.io',
  'https://mariozumaran.github.io',
  'https://dmz-audit.netlify.app',
  'https://racreaa.vercel.app',
].filter(Boolean);

function sha256(d) { return crypto.createHash('sha256').update(JSON.stringify(d)).digest('hex'); }
function sanitize(v, max=500) { return typeof v==='string' ? v.slice(0,max).replace(/[<>]/g,'') : ''; }
function genId() { return 'AUD-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase(); }

function verifyToken(h) {
  if (!h?.startsWith('Bearer ')) throw new Error('AUTH_MISSING');
  try { return jwt.verify(h.slice(7), JWT_SECRET); }
  catch { throw new Error('AUTH_INVALID'); }
}

function getNivel(s) {
  if (s>=85) return { label:'Excelente', color:'#1A5E3A' };
  if (s>=70) return { label:'Bueno',     color:'#2E7D52' };
  if (s>=55) return { label:'Regular',   color:'#A07820' };
  if (s>=40) return { label:'Deficiente',color:'#C06020' };
  return             { label:'Crítico',  color:'#B83232' };
}

async function sendReport({ auditId, body, serverTs, tenantId }) {
  const nivel = getNivel(body.globalScore || 0);
  const tipo  = (body.tipo || 'alimentos').toUpperCase();

  const itemsHtml = (body.items || []).map(item => {
    const niv = getNivel(item.score||0);
    const timer = (item.timerStart && item.timerEnd)
      ? `<span style="font-size:10px;color:#9A9890"> · ${item.timerDuration||''}</span>`
      : '';
    const fotos = (item.evidence||[]).length
      ? `<span style="font-size:10px;color:#2E7D52"> 📷 ${item.evidence.length} foto${item.evidence.length>1?'s':''}</span>`
      : '';
    return `<tr>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:12px">${item.num}. ${item.nombre||'—'}${timer}${fotos}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:12px;color:#5C5A54">${item.categoria||'—'}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:12px;font-weight:700;text-align:center;color:${niv.color}">${item.score||0}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:11px;color:#9A9890">${niv.label}</td>
    </tr>`;
  }).join('');

  const html = `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"></head>
  <body style="background:#FAFAF7;font-family:Arial,sans-serif;color:#2C2A24;margin:0;padding:0">
    <div style="max-width:600px;margin:0 auto;background:#fff;border-top:3px solid #C4922A">
      <div style="background:#2C2A24;padding:24px 32px">
        <div style="font-weight:900;font-size:18px;letter-spacing:5px;color:#C4922A;text-transform:uppercase">DMZ AUDIT</div>
        <div style="font-size:9px;letter-spacing:3px;color:rgba(255,255,255,.4);text-transform:uppercase;margin-top:4px">Evaluación de ${tipo} · dmzkitchensupport.github.io</div>
      </div>
      <div style="padding:24px 32px;border-bottom:1px solid #E0DDD4">
        <table style="width:100%;border-collapse:collapse">
          <tr><td style="padding:5px 0;font-size:10px;color:#9A9890;text-transform:uppercase;letter-spacing:1px;width:140px">ID</td><td style="font-size:11px;font-family:monospace">${auditId}</td></tr>
          <tr><td style="padding:5px 0;font-size:10px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Establecimiento</td><td style="font-size:12px">${sanitize(body.establecimiento)||'—'}</td></tr>
          <tr><td style="padding:5px 0;font-size:10px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Auditor</td><td style="font-size:12px">${sanitize(body.auditorFirma||body.auditor)||'—'}</td></tr>
          <tr><td style="padding:5px 0;font-size:10px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Fecha</td><td style="font-size:12px">${body.fecha||'—'} · ${sanitize(body.servicio)||'—'}</td></tr>
          ${body.mesero ? `<tr><td style="padding:5px 0;font-size:10px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Mesero</td><td style="font-size:12px">${sanitize(body.mesero)}</td></tr>` : ''}
          <tr><td style="padding:5px 0;font-size:10px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Timestamp</td><td style="font-size:10px;font-family:monospace;color:#5C5A54">${serverTs}</td></tr>
          ${body.gpsAtSubmission ? `<tr><td style="padding:5px 0;font-size:10px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">GPS</td><td style="font-size:10px;font-family:monospace;color:#2E7D52">✅ ${body.gpsAtSubmission.lat?.toFixed(5)}, ${body.gpsAtSubmission.lng?.toFixed(5)} ±${Math.round(body.gpsAtSubmission.accuracy||0)}m</td></tr>` : ''}
        </table>
      </div>
      <div style="padding:20px 32px;text-align:center;border-bottom:1px solid #E0DDD4">
        <div style="display:inline-block;background:${nivel.color};padding:14px 32px">
          <div style="font-size:40px;font-weight:900;color:#fff;line-height:1">${body.globalScore||0}</div>
          <div style="font-size:9px;font-weight:700;letter-spacing:3px;color:rgba(255,255,255,.7);text-transform:uppercase;margin-top:3px">${nivel.label}</div>
        </div>
      </div>
      ${(body.items||[]).length ? `
      <div style="padding:20px 32px;border-bottom:1px solid #E0DDD4">
        <div style="font-size:9px;font-weight:700;letter-spacing:3px;color:#8A6C1E;text-transform:uppercase;margin-bottom:10px">Detalle</div>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr style="background:#F3F1EB">
            <th style="padding:7px 12px;text-align:left;font-size:9px;letter-spacing:1px;color:#9A9890;text-transform:uppercase">Platillo / Criterio</th>
            <th style="padding:7px 12px;text-align:left;font-size:9px;color:#9A9890;text-transform:uppercase">Categoría</th>
            <th style="padding:7px 12px;text-align:center;font-size:9px;color:#9A9890;text-transform:uppercase">Score</th>
            <th style="padding:7px 12px;text-align:left;font-size:9px;color:#9A9890;text-transform:uppercase">Nivel</th>
          </tr></thead>
          <tbody>${itemsHtml}</tbody>
        </table>
      </div>` : ''}
      ${body.conclusion ? `<div style="padding:20px 32px;border-bottom:1px solid #E0DDD4"><div style="font-size:9px;font-weight:700;letter-spacing:3px;color:#8A6C1E;text-transform:uppercase;margin-bottom:8px">Dictamen</div><p style="font-size:12px;color:#5C5A54;line-height:1.7;margin:0">${sanitize(body.conclusion,2000)}</p></div>` : ''}
      <div style="padding:16px 32px;background:#F3F1EB;text-align:center;font-size:9px;color:#9A9890">
        DMZ Kitchen Support · DMZ Audit · <code>${auditId}</code>
      </div>
    </div>
  </body></html>`;

  await resend.emails.send({
    from:    'DMZ Audit <onboarding@resend.dev>',
    to:      [REPORT_EMAIL],
    subject: `[DMZ Audit] ${auditId} — ${sanitize(body.establecimiento)||'Sin nombre'} — ${body.globalScore||0} pts (${getNivel(body.globalScore||0).label})`,
    html,
  });
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin||'';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Client-GPS, X-Request-ID');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method==='OPTIONS') return res.status(204).end();
  if (req.method!=='POST')   return res.status(405).json({success:false,message:'Method Not Allowed'});
  res.setHeader('Cache-Control','no-store');

  let claims;
  try { claims = verifyToken(req.headers.authorization); }
  catch { return res.status(401).json({success:false,message:'No autorizado.'}); }

  const tenantId   = claims.tenant_id;
  const operatorId = claims.sub;
  const ip         = (req.headers['x-forwarded-for']||'').split(',')[0].trim()||'unknown';
  const ua         = req.headers['user-agent']||'';
  const reqId      = req.headers['x-request-id']||crypto.randomUUID();
  const body       = req.body;

  if (!body || typeof body !== 'object') return res.status(400).json({success:false,message:'Payload inválido.'});

  const auditId  = genId();
  const serverTs = new Date().toISOString();
  const client   = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Insertar auditoría principal
    await client.query(`
      INSERT INTO racreaa.audits
        (id,tenant_id,operator_id,establecimiento,auditor_name,audit_date,service_period,
         global_score,conclusion,auditor_firma,chef_firma,
         gps_lat,gps_lng,gps_accuracy,client_ip,user_agent,
         session_token,request_id,client_submitted_at,server_timestamp,
         audit_type,mesa,mesero)
      VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
    `,[
      auditId, tenantId, operatorId,
      sanitize(body.establecimiento),
      sanitize(body.auditorFirma || body.auditor),  // ← fix auditor_name
      body.fecha||null,
      sanitize(body.servicio,100),
      body.globalScore||0,
      sanitize(body.conclusion,2000),
      sanitize(body.auditorFirma),
      sanitize(body.chefFirma),
      body.gpsAtSubmission?.lat||null,
      body.gpsAtSubmission?.lng||null,
      body.gpsAtSubmission?.accuracy||null,
      ip, ua,
      sanitize(body.sessionToken,64),
      reqId,
      body.submittedAt||null,
      serverTs,
      sanitize(body.tipo||'alimentos',20),
      sanitize(body.mesa||'',100),
      sanitize(body.mesero||'',100),
    ]);

    // 2. Insertar items + evidence (fotos)
    let totalFotos = 0;
    for (const item of (body.items||[]).slice(0,50)) {
      const itemId = `${auditId}-I${item.num}`;

      await client.query(`
        INSERT INTO racreaa.audit_items
          (id,audit_id,tenant_id,item_num,nombre,categoria,score,nivel,observaciones,
           crit_presentacion,crit_temperatura,crit_sabor,crit_textura,crit_porcion,
           timer_start,timer_end,server_timestamp)
        VALUES ($1,$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
      `,[
        itemId, auditId, tenantId,
        item.num,
        sanitize(item.nombre),
        sanitize(item.categoria),
        item.score||0,
        item.nivel||null,
        sanitize(item.observaciones||'',1000),
        item.criterios?.presentacion||0,
        item.criterios?.temperatura||0,
        item.criterios?.sabor||0,
        item.criterios?.textura||0,
        item.criterios?.porcion||0,
        item.timerStart ? new Date(item.timerStart) : null,
        item.timerEnd   ? new Date(item.timerEnd)   : null,
        serverTs,
      ]);

      // 3. Guardar fotos en audit_evidence
      for (const ev of (item.evidence||[]).slice(0,10)) {
        if (!ev.base64) continue;
        totalFotos++;
        const evId = `${itemId}-EV${totalFotos}`;
        const imgHash = sha256({ evId, capturedAt: ev.capturedAt });

        await client.query(`
          INSERT INTO racreaa.audit_evidence
            (id,audit_id,audit_item_id,tenant_id,operator_id,
             image_data,mime_type,size_bytes,
             gps_lat,gps_lng,gps_verified,
             captured_at_client,server_timestamp,integrity_hash)
          VALUES ($1,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        `,[
          evId, auditId, itemId, tenantId, operatorId,
          ev.base64,                          // ← foto base64 guardada
          ev.mimeType||'image/jpeg',
          ev.sizeBytes||0,
          ev.gps?.lat||null,
          ev.gps?.lng||null,
          ev.gpsVerified||false,
          ev.capturedAt ? new Date(ev.capturedAt) : null,
          serverTs,
          imgHash,
        ]);
      }
    }

    // 4. Audit log inmutable
    await client.query(`
      INSERT INTO racreaa.audit_logs
        (id,tenant_id,operator_id,audit_id,action,entity_type,entity_id,
         client_ip,user_agent,request_id,payload_hash,occurred_at)
      VALUES (gen_random_uuid(),$1,$2,$3,'AUDIT_SUBMITTED','audit',$3,$4,$5,$6,$7,NOW())
    `,[tenantId,operatorId,auditId,ip,ua,reqId,
       sha256({auditId,tenantId,operatorId,serverTs,totalFotos})]);

    await client.query('COMMIT');

    // Email asíncrono
    sendReport({ auditId, body, serverTs, tenantId }).catch(e =>
      console.error('[email]', e.message)
    );

    return res.status(200).json({
      success: true,
      auditId,
      timestamp: serverTs,
      fotos_guardadas: totalFotos,
      message: `Evaluación registrada. ${totalFotos} foto${totalFotos!==1?'s':''} guardada${totalFotos!==1?'s':''}.`
    });

  } catch(err) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('[submit-audit]', err.message);
    return res.status(500).json({success:false, message:'Error interno al guardar.'});
  } finally {
    client.release();
  }
};
