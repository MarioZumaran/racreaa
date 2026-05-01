const handler_module = require('./auth-refresh_impl');

exports.handler = async (event, context) => {
  // Adaptar Netlify event → Vercel req/res
  const req = {
    method: event.httpMethod,
    headers: event.headers || {},
    body: (() => {
      if (!event.body) return {};
      try { return JSON.parse(event.body); } catch { return {}; }
    })(),
    query: event.queryStringParameters || {},
    socket: { remoteAddress: event.headers['x-forwarded-for'] || '' },
  };

  let statusCode = 200;
  const responseHeaders = {'Content-Type': 'application/json'};
  let responseBody = '';
  let ended = false;

  const res = {
    setHeader: (k, v) => { responseHeaders[k] = v; },
    status: (code) => { statusCode = code; return res; },
    json: (data) => { responseBody = JSON.stringify(data); ended = true; return res; },
    end: (body) => { if (body) responseBody = body; ended = true; return res; },
    send: (body) => { responseBody = typeof body === 'object' ? JSON.stringify(body) : body; ended = true; return res; },
  };

  await handler_module(req, res);

  return {
    statusCode,
    headers: responseHeaders,
    body: responseBody,
  };
};
