import { createHmac, timingSafeEqual } from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function sign(data, secret) {
  return createHmac('sha256', secret).update(data).digest('base64url');
}

/** Serialises `payload` into a tamper-proof `data.signature` token that expires after `maxAge` seconds. */
export function seal(payload, secret, maxAge) {
  const body = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + maxAge }));
  return `${body}.${sign(body, secret)}`;
}

/** Returns the payload of a valid, unexpired token or `null`. */
export function unseal(token, secret) {
  if (typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const given = Buffer.from(token.slice(dot + 1));
  const expected = Buffer.from(sign(body, secret));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key || key in out) continue;
    try {
      out[key] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[key] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

export function serializeCookie(name, value, { maxAge, path = '/', secure = true, sameSite = 'Lax', httpOnly = true } = {}) {
  let str = `${name}=${encodeURIComponent(value)}; Path=${path}`;
  if (maxAge !== undefined) str += `; Max-Age=${Math.floor(maxAge)}`;
  if (httpOnly) str += '; HttpOnly';
  if (secure) str += '; Secure';
  if (sameSite) str += `; SameSite=${sameSite}`;
  return str;
}

export function appendSetCookie(res, cookie) {
  const prev = res.getHeader('Set-Cookie');
  const list = prev === undefined ? [] : Array.isArray(prev) ? prev : [String(prev)];
  res.setHeader('Set-Cookie', [...list, cookie]);
}
