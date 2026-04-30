/**
 * /api/submit-audit.js
 * RACREAA — Serverless Function (Vercel)
 * Recibe el payload de auditoría, valida JWT, sube evidencia a Vercel Blob,
 * persiste en PostgreSQL con RLS y despacha notificación por Resend.
 *
 * Env vars requeridas (Vercel Dashboard > Settings > Environment Variables):
 *   DATABASE_URL         — PostgreSQL connection string (Neon / Supabase / Railway)
 *   JWT_SECRET           — Secreto HS256 para verificar tokens de sesión
 *   BLOB_READ_WRITE_TOKEN — Token de Vercel Blob Storage
 *   RESEND_API_KEY       — API key de Resend para notificaciones transaccionales
 *   AUDIT_REPORT_EMAIL   — Dirección de destino del reporte
 *   ALLOWED_ORIGINS      — Orígenes CORS permitidos (CSV)
 */

import { put }     from '@vercel/blob';
import { Resend }  from 'resend';
import { Pool }    from 'pg';
import jwt         from 'jsonwebtoken';
import crypto      from 'crypto';

/* ─────────────────────────────────────────
   CONFIGURACIÓN
   ───────────────────────────────────────── */
const pool   = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });
const resend = new Resend(process.env.RESEND_API_KEY);

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
const MAX_PAYLOAD_MB  = 50; // límite de payload (evidencia incluida)

/* ─────────────────────────────────────────
   HELPERS
   ───────────────────────────────────────── */

/**
 * Verifica JWT y extrae claims del operador.
 * En el prototipo acepta el SESSION_TOKEN del cliente como sub.
 * En producción: el token debe estar firmado por el servidor al hacer login.
 */
function verifyToken(authHeader) {
  if (!authHeader?.startsWith('Bearer ')) throw new Error('AUTH_MISSING');
  const token = authHeader.slice(7);
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    // Para el prototipo, si no hay JWT firmado, extraemos el session ID del header
    // y lo usamos como operador_id anónimo con tenant_id = 'demo'
    if (process.env.NODE_ENV === 'development') {
      return { sub: token, tenant_id: 'demo', role: 'auditor' };
    }
    throw new Error('AUTH_INVALID');
  }
}

/**
 * Genera hash SHA-256 de los datos del ítem para el audit trail inmutable.
 */
function hashPayload(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

/**
 * Genera un ID único para el audit trail.
 */
function generateAuditId() {
  return 'AUD-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

/**
 * Sube una imagen en base64 a Vercel Blob y retorna la URL firmada.
 * El path incluye tenant_id / audit_id / evidence_id para aislamiento.
 */
async function uploadEvidenceToBlob(base64, mimeType, tenantId, auditId, evidenceId) {
  const ext    = mimeType.split('/')[1] || 'jpg';
  const buffer = Buffer.from(base64.replace(/^data:[^;]+;base64,/, ''), 'base64');
  const path   = `${tenantId}/${auditId}/${evidenceId}.${ext}`;

  const { url } = await put(path, buffer, {
    access:      'private',           // URL firmadas, no públicas
    contentType: mimeType,
    addRandomSuffix: false,
  });

  return url;
}

/**
 * Valida y sanitiza el payload antes de persistir.
 * Evita inyección SQL y desbordamientos de campo.
 */
function sanitizePayload(body) {
  const str = (v, max=500) => typeof v === 'string' ? v.slice(0, max).replace(/[<>]/g, '') : '';
  const num = (v, def=0)   => typeof v === 'number' && isFinite(v) ? v : def;

  return {
    sessionToken:    str(body.sessionToken, 64),
    submittedAt:     body.submittedAt || new Date().toISOString(),
    gpsAtSubmission: body.gpsAtSubmission || null,
    establecimiento: str(body.establecimiento),
    auditor:         str(body.auditor),
    fecha:           str(body.fecha, 10),
    servicio:        str(body.servicio, 100),
    auditorFirma:    str(body.auditorFirma),
    chefFirma:       str(body.chefFirma),
    signatureImage:  typeof body.signatureImage === 'string' ? body.signatureImage : null,
    conclusion:      str(body.conclusion, 2000),
    globalScore:     num(body.globalScore),
    items:           Array.isArray(body.items) ? body.items.slice(0, 50) : [],
  };
}

/* ─────────────────────────────────────────
   HANDLER PRINCIPAL
   ───────────────────────────────────────── */
export default async function handler(req, res) {

  /* ── CORS ── */
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',  origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Client-GPS, X-Request-ID');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();

  /* ── Solo POST ── */
  if (req.method !== 'POST') {
    return res.status(405).json({ success:false, message:'Method Not Allowed' });
  }

  /* ── Security headers ── */
  res.setHeader('X-Content-Type-Options',      'nosniff');
  res.setHeader('X-Frame-Options',             'DENY');
  res.setHeader('Strict-Transport-Security',   'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Cache-Control',               'no-store');

  /* ── Autenticación JWT ── */
  let tokenClaims;
  try {
    tokenClaims = verifyToken(req.headers.authorization);
  } catch (e) {
    return res.status(401).json({ success:false, message:'No autorizado.' });
  }

  const tenantId   = tokenClaims.tenant_id || 'demo';
  const operatorId = tokenClaims.sub;
  const clientGPS  = req.headers['x-client-gps'] || null;
  const requestId  = req.headers['x-request-id'] || crypto.randomUUID();
  const clientIP   = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const userAgent  = req.headers['user-agent'] || '';

  /* ── Parse & sanitize body ── */
  const raw = req.body;
  if (!raw || typeof raw !== 'object') {
    return res.status(400).json({ success:false, message:'Payload inválido.' });
  }

  const data    = sanitizePayload(raw);
  const auditId = generateAuditId();

  /* ── Timestamp del servidor (autoritativo) ── */
  const serverTimestamp = new Date().toISOString();

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    /* ── SET RLS context: permite que las políticas de PG filtren por tenant ── */
    await client.query(`SET LOCAL app.current_tenant_id = $1`, [tenantId]);
    await client.query(`SET LOCAL app.current_operator_id = $1`, [operatorId]);

    /* ── Insertar auditoría principal ── */
    const auditResult = await client.query(`
      INSERT INTO audits (
        id, tenant_id, operator_id,
        establecimiento, auditor_name, audit_date, service_period,
        global_score, conclusion,
        auditor_firma, chef_firma, signature_image,
        gps_lat, gps_lng, gps_accuracy,
        client_gps_header, client_ip, user_agent,
        session_token, request_id,
        client_submitted_at, server_timestamp
      ) VALUES (
        $1, $2, $3,
        $4, $5, $6, $7,
        $8, $9,
        $10, $11, $12,
        $13, $14, $15,
        $16, $17, $18,
        $19, $20,
        $21, $22
      )
      RETURNING id
    `, [
      auditId, tenantId, operatorId,
      data.establecimiento, data.auditor, data.fecha, data.servicio,
      data.globalScore, data.conclusion,
      data.auditorFirma, data.chefFirma, data.signatureImage,
      data.gpsAtSubmission?.lat  || null,
      data.gpsAtSubmission?.lng  || null,
      data.gpsAtSubmission?.accuracy || null,
      clientGPS, clientIP, userAgent,
      data.sessionToken, requestId,
      data.submittedAt, serverTimestamp
    ]);

    /* ── Insertar ítems y subir evidencia ── */
    const evidenceRegistry = [];

    for (const item of data.items) {
      const itemId = `${auditId}-ITEM-${item.num}`;

      await client.query(`
        INSERT INTO audit_items (
          id, audit_id, tenant_id,
          item_num, nombre, categoria,
          score, nivel, observaciones,
          crit_presentacion, crit_temperatura, crit_sabor, crit_textura, crit_porcion,
          server_timestamp
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      `, [
        itemId, auditId, tenantId,
        item.num, item.nombre, item.categoria,
        item.score, item.nivel, item.observaciones,
        item.criterios?.presentacion || 0,
        item.criterios?.temperatura  || 0,
        item.criterios?.sabor        || 0,
        item.criterios?.textura      || 0,
        item.criterios?.porcion      || 0,
        serverTimestamp
      ]);

      /* ── Subir evidencia fotográfica ── */
      for (const ev of (item.evidence || [])) {
        if (!ev.base64 || !ev.mimeType) continue;

        const blobUrl = await uploadEvidenceToBlob(
          ev.base64, ev.mimeType, tenantId, auditId, ev.id
        );

        const evDbId = `${itemId}-EV-${ev.id}`;
        await client.query(`
          INSERT INTO audit_evidence (
            id, audit_id, audit_item_id, tenant_id,
            blob_url, mime_type, size_bytes,
            gps_lat, gps_lng, gps_verified,
            captured_at_client, server_timestamp,
            operator_id, integrity_hash
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        `, [
          evDbId, auditId, itemId, tenantId,
          blobUrl, ev.mimeType, ev.sizeBytes,
          ev.gps?.lat  || null,
          ev.gps?.lng  || null,
          ev.gpsVerified || false,
          ev.capturedAt, serverTimestamp,
          operatorId,
          hashPayload({ blobUrl, capturedAt: ev.capturedAt, gps: ev.gps, operatorId })
        ]);

        evidenceRegistry.push({ itemNum: item.num, blobUrl, gpsVerified: ev.gpsVerified });
      }
    }

    /* ── Audit Trail Inmutable ── */
    const payloadHash = hashPayload({
      auditId, tenantId, operatorId, serverTimestamp,
      globalScore: data.globalScore, itemCount: data.items.length
    });

    await client.query(`
      INSERT INTO audit_logs (
        id, tenant_id, operator_id, audit_id,
        action, entity_type, entity_id,
        client_ip, user_agent, request_id,
        gps_lat, gps_lng,
        payload_hash, occurred_at
      ) VALUES (
        gen_random_uuid(), $1, $2, $3,
        'AUDIT_SUBMITTED', 'audit', $3,
        $4, $5, $6,
        $7, $8,
        $9, NOW()
      )
    `, [
      tenantId, operatorId, auditId,
      clientIP, userAgent, requestId,
      data.gpsAtSubmission?.lat || null,
      data.gpsAtSubmission?.lng || null,
      payloadHash
    ]);

    await client.query('COMMIT');

    /* ── Notificación Transaccional via Resend ── */
    try {
      await sendAuditEmail({
        auditId,
        data,
        serverTimestamp,
        tenantId,
        evidenceRegistry
      });
    } catch (emailErr) {
      // El email no debe bloquear el éxito de la operación principal
      console.error('[RACREAA] Email dispatch failed:', emailErr.message);
    }

    return res.status(200).json({
      success:   true,
      auditId,
      timestamp: serverTimestamp,
      message:   'Evaluación registrada correctamente.'
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[RACREAA] submit-audit error:', err);

    // Log del error sin exponer detalles al cliente
    try {
      await pool.query(`
        INSERT INTO audit_logs (
          id, tenant_id, operator_id,
          action, entity_type,
          client_ip, request_id, payload_hash, occurred_at
        ) VALUES (
          gen_random_uuid(), $1, $2,
          'AUDIT_SUBMIT_ERROR', 'audit',
          $3, $4, $5, NOW()
        )
      `, [
        tenantId, operatorId, clientIP, requestId,
        hashPayload({ error: err.message, requestId })
      ]);
    } catch (_) {}

    return res.status(500).json({ success:false, message:'Error interno. El incidente ha sido registrado.' });
  } finally {
    client.release();
  }
}

/* ─────────────────────────────────────────
   EMAIL TRANSACCIONAL — RESEND
   ───────────────────────────────────────── */
async function sendAuditEmail({ auditId, data, serverTimestamp, tenantId, evidenceRegistry }) {
  const nivel     = getNivelFromScore(data.globalScore);
  const nivelColor = { critico:'#B83232', deficiente:'#C06020', regular:'#A07820', bueno:'#2E7D52', excelente:'#1A5E3A' }[nivel] || '#2C2A24';

  const itemsHtml = data.items.map(item => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:12px;color:#2C2A24">${item.num}. ${item.nombre}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:12px;color:#5C5A54">${item.categoria}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:12px;font-weight:700;text-align:center;color:${nivelColor}">${item.score}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #E0DDD4;font-size:11px;color:#9A9890">${item.nivel}</td>
    </tr>
  `).join('');

  const html = `
  <!DOCTYPE html>
  <html lang="es">
  <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
  <body style="background:#FAFAF7;font-family:'Helvetica Neue',Arial,sans-serif;color:#2C2A24;margin:0;padding:0">
    <div style="max-width:600px;margin:0 auto;background:#FFFFFF;border-top:3px solid #B8922A">

      <!-- Header -->
      <div style="background:#2C2A24;padding:24px 32px">
        <div style="font-family:'Helvetica Neue',Arial,sans-serif;font-weight:900;font-size:20px;letter-spacing:6px;color:#B8922A;text-transform:uppercase">DMZ</div>
        <div style="font-size:10px;letter-spacing:3px;color:rgba(255,255,255,.4);text-transform:uppercase;margin-top:4px">Reporte de Calificación de Alimentos</div>
      </div>

      <!-- Meta -->
      <div style="padding:24px 32px;border-bottom:1px solid #E0DDD4">
        <table style="width:100%;border-collapse:collapse">
          <tr>
            <td style="padding:6px 0;font-size:11px;color:#9A9890;text-transform:uppercase;letter-spacing:1px;width:140px">ID de Auditoría</td>
            <td style="padding:6px 0;font-size:12px;font-family:monospace;color:#2C2A24">${auditId}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;font-size:11px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Establecimiento</td>
            <td style="padding:6px 0;font-size:12px;color:#2C2A24">${data.establecimiento || '—'}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;font-size:11px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Auditor</td>
            <td style="padding:6px 0;font-size:12px;color:#2C2A24">${data.auditorFirma || data.auditor || '—'}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;font-size:11px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Fecha</td>
            <td style="padding:6px 0;font-size:12px;color:#2C2A24">${data.fecha || '—'} · ${data.servicio || '—'}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;font-size:11px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Timestamp Servidor</td>
            <td style="padding:6px 0;font-size:11px;font-family:monospace;color:#5C5A54">${serverTimestamp}</td>
          </tr>
          ${data.gpsAtSubmission ? `
          <tr>
            <td style="padding:6px 0;font-size:11px;color:#9A9890;text-transform:uppercase;letter-spacing:1px">Coordenadas GPS</td>
            <td style="padding:6px 0;font-size:11px;font-family:monospace;color:#5C5A54">${data.gpsAtSubmission.lat?.toFixed(6)}, ${data.gpsAtSubmission.lng?.toFixed(6)} ±${Math.round(data.gpsAtSubmission.accuracy)}m</td>
          </tr>` : ''}
        </table>
      </div>

      <!-- Score global -->
      <div style="padding:24px 32px;text-align:center;border-bottom:1px solid #E0DDD4">
        <div style="display:inline-block;background:${nivelColor};padding:16px 32px">
          <div style="font-size:42px;font-weight:900;color:#FFFFFF;line-height:1">${data.globalScore}</div>
          <div style="font-size:10px;font-weight:700;letter-spacing:3px;color:rgba(255,255,255,.7);text-transform:uppercase;margin-top:4px">${nivel.toUpperCase()}</div>
        </div>
      </div>

      <!-- Tabla de platillos -->
      <div style="padding:24px 32px;border-bottom:1px solid #E0DDD4">
        <div style="font-size:10px;font-weight:700;letter-spacing:3px;color:#8A6C1E;text-transform:uppercase;margin-bottom:12px">Detalle por Platillo</div>
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="background:#F3F1EB">
              <th style="padding:8px 12px;text-align:left;font-size:10px;letter-spacing:1px;color:#9A9890;text-transform:uppercase;font-weight:600">Platillo</th>
              <th style="padding:8px 12px;text-align:left;font-size:10px;letter-spacing:1px;color:#9A9890;text-transform:uppercase;font-weight:600">Categoría</th>
              <th style="padding:8px 12px;text-align:center;font-size:10px;letter-spacing:1px;color:#9A9890;text-transform:uppercase;font-weight:600">Score</th>
              <th style="padding:8px 12px;text-align:left;font-size:10px;letter-spacing:1px;color:#9A9890;text-transform:uppercase;font-weight:600">Nivel</th>
            </tr>
          </thead>
          <tbody>${itemsHtml}</tbody>
        </table>
      </div>

      <!-- Conclusión -->
      ${data.conclusion ? `
      <div style="padding:24px 32px;border-bottom:1px solid #E0DDD4">
        <div style="font-size:10px;font-weight:700;letter-spacing:3px;color:#8A6C1E;text-transform:uppercase;margin-bottom:10px">Conclusión</div>
        <p style="font-size:13px;color:#5C5A54;line-height:1.7;margin:0">${data.conclusion}</p>
      </div>` : ''}

      <!-- Footer -->
      <div style="padding:18px 32px;background:#F3F1EB">
        <div style="font-size:10px;color:#9A9890;text-align:center;line-height:1.8">
          Generado por <strong style="color:#B8922A">DMZ Kitchen Support · RACREAA</strong><br>
          Tenant: <code style="font-family:monospace">${tenantId}</code> · ID: <code style="font-family:monospace">${auditId}</code><br>
          Este reporte es confidencial y de uso exclusivo del cliente autorizado.
        </div>
      </div>

    </div>
  </body>
  </html>
  `;

  await resend.emails.send({
    from:    'RACREAA <reportes@dmzkitchensupport.com>',
    to:      [process.env.AUDIT_REPORT_EMAIL],
    subject: `[RACREAA] Auditoría ${auditId} — ${data.establecimiento || 'Sin nombre'} — Score: ${data.globalScore}`,
    html,
    tags: [
      { name: 'audit_id',   value: auditId   },
      { name: 'tenant_id',  value: tenantId  },
      { name: 'score',      value: String(data.globalScore) },
    ]
  });
}

function getNivelFromScore(score) {
  if (score >= 85) return 'excelente';
  if (score >= 70) return 'bueno';
  if (score >= 55) return 'regular';
  if (score >= 40) return 'deficiente';
  return 'critico';
}
