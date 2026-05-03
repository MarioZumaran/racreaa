/**
 * audit-session.js — Netlify Function wrapper
 * Routes to audit-session_impl.js
 */
const impl = require('./audit-session_impl');

exports.handler = async (event, context) => {
  const req = {
    method:  event.httpMethod,
    headers: event.headers || {},
    query:   event.queryStringParameters || {},
    body:    event.body ? JSON.parse(event.body) : {},
  };
  const chunks = [];
  const res = {
    statusCode: 200,
    headers: {},
    _body: '',
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(data) { this._body = JSON.stringify(data); this.headers['Content-Type'] = 'application/json'; },
    end() {},
  };

  await impl(req, res);

  return {
    statusCode: res.statusCode,
    headers:    res.headers,
    body:       res._body,
  };
};
