const handler_module = require('./monitor_impl');

const CORS_ORIGINS = [
  'https://mariozumaran.github.io',
  'https://dmzkitchensupport.github.io',
  'https://dmz-audit.netlify.app',
  'https://racreaa.vercel.app',
  ...(process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
];

exports.handler = async (event, context) => {
  const origin = event.headers['origin'] || event.headers['Origin'] || '';
  const allowOrigin = CORS_ORIGINS.includes(origin) ? origin : CORS_ORIGINS[0];

  // CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID, X-Client-GPS',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
      },
      body: '',
    };
  }

  const req = {
    method: event.httpMethod,
    headers: event.headers || {},
    body: (() => {
      if (!event.body) return {};
      try { return JSON.parse(event.body); } catch { return {}; }
    })(),
    query: event.queryStringParameters || {},
    socket: { remoteAddress: (event.headers['x-forwarded-for'] || '').split(',')[0].trim() || '' },
  };

  let statusCode = 200;
  const responseHeaders = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID, X-Client-GPS',
    'Vary': 'Origin',
  };
  let responseBody = '';

  const res = {
    setHeader: (k, v) => { responseHeaders[k] = v; },
    status: (code) => { statusCode = code; return res; },
    json: (data) => { responseBody = JSON.stringify(data); return res; },
    end: (body) => { if (body) responseBody = body; return res; },
    send: (body) => { responseBody = typeof body === 'object' ? JSON.stringify(body) : body; return res; },
  };

  await handler_module(req, res);

  return { statusCode, headers: responseHeaders, body: responseBody };
};
