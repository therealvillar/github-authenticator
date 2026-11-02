import { randomBytes } from 'node:crypto';
import { normalizeConfig } from './config.js';
import { createPermissions } from './permissions.js';
import { checkDomain } from './domain.js';
import { createGitHubClient } from './github.js';
import { createPasswordReset } from './passwordReset.js';
import { seal, unseal, parseCookies, serializeCookie, appendSetCookie } from './session.js';

const MAX_BODY = 16 * 1024;

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function wantsJson(req) {
  const accept = String(req.headers.accept || '');
  const type = String(req.headers['content-type'] || '');
  return type.includes('application/json') || (accept.includes('application/json') && !accept.includes('text/html'));
}

function send(res, status, body, type = 'text/html; charset=utf-8') {
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}

function sendJson(res, status, data) {
  send(res, status, JSON.stringify(data), 'application/json; charset=utf-8');
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'no-store');
  res.end();
}

function page(title, inner) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head>` +
    `<body><main><h1>${escapeHtml(title)}</h1>${inner}</main></body></html>`;
}

function message(req, res, status, text, extra = {}) {
  if (wantsJson(req)) return sendJson(res, status, { message: text, ...extra });
  return send(res, status, page(status >= 400 ? 'Error' : 'Done', `<p>${escapeHtml(text)}</p>`));
}

/** Only allow same-site relative paths to prevent open redirects. */
export function safeReturnTo(value, fallback) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) return fallback;
  if (/[\\\u0000-\u001f]/.test(value)) return fallback;
  return value;
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error('Request body too large'), { status: 413 });
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  if (String(req.headers['content-type'] || '').includes('application/json')) {
    try {
      return JSON.parse(raw);
    } catch {
      throw Object.assign(new Error('Invalid JSON body'), { status: 400 });
    }
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

/**
 * Creates a reusable authenticator from a configuration object (see authenticator.config.example.js).
 *
 * @param {object} rawConfig configuration (raw or already normalised)
 * @param {{ fetch?: typeof fetch }} [options]
 */
export function createAuthenticator(rawConfig, options = {}) {
  const config = normalizeConfig(rawConfig);
  const permissions = createPermissions(config);
  const github = createGitHubClient(config.github, options.fetch);
  const passwordReset = createPasswordReset(config);
  const { basePath } = config.routes;
  const { cookieName, secret, maxAge, secure, sameSite } = config.session;
  const stateCookie = `${cookieName}_state`;

  const routes = {
    login: `${basePath}/login`,
    callback: `${basePath}/callback`,
    logout: `${basePath}/logout`,
    me: `${basePath}/me`,
    passwordReset: `${basePath}/password-reset`,
    passwordResetConfirm: `${basePath}/password-reset/confirm`,
  };

  /** Returns the signed-in user for a request or null. Access is re-validated against the current config. */
  function getUser(req) {
    const cookies = parseCookies(req.headers.cookie);
    const payload = unseal(cookies[cookieName], secret);
    if (!payload || payload.type !== 'session') return null;
    const emails = payload.email ? [{ email: payload.email, verified: true, primary: true }] : [];
    if (!checkDomain(config, { login: payload.login, emails }).ok) return null;
    const { type, exp, ...user } = payload;
    return user;
  }

  function describe(user) {
    return {
      user,
      roles: permissions.getRoles(user),
      features: permissions.getFeatures(user),
    };
  }

  function attach(req) {
    const user = getUser(req);
    req.user = user;
    req.auth = {
      user,
      roles: permissions.getRoles(user),
      hasFeature: (name) => permissions.hasFeature(user, name),
      canAccess: (pathname) => permissions.canAccessPage(user, pathname),
    };
    return user;
  }

  function deny(req, res, user, pathname) {
    if (!user) {
      if (wantsJson(req)) return sendJson(res, 401, { message: 'Authentication required' });
      return redirect(res, `${routes.login}?${new URLSearchParams({ returnTo: pathname })}`);
    }
    return message(req, res, 403, 'You do not have permission to access this resource');
  }

  async function handleLogin(req, res, url) {
    const state = randomBytes(24).toString('base64url');
    const returnTo = safeReturnTo(url.searchParams.get('returnTo'), config.routes.afterLogin);
    appendSetCookie(res, serializeCookie(stateCookie, seal({ type: 'state', state, returnTo }, secret, 600), {
      maxAge: 600, path: basePath, secure, sameSite: 'Lax',
    }));
    redirect(res, github.authorizeUrl({ state, redirectUri: config.github.callbackUrl }));
  }

  async function handleCallback(req, res, url) {
    const cookies = parseCookies(req.headers.cookie);
    const saved = unseal(cookies[stateCookie], secret);
    appendSetCookie(res, serializeCookie(stateCookie, '', { maxAge: 0, path: basePath, secure, sameSite: 'Lax' }));

    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!saved || saved.type !== 'state' || !state || saved.state !== state) {
      return message(req, res, 400, 'Invalid or expired login attempt, please try again');
    }
    if (!code) return message(req, res, 400, url.searchParams.get('error_description') || 'Missing authorization code');

    let identity;
    try {
      const token = await github.exchangeCode({ code, redirectUri: config.github.callbackUrl });
      identity = await github.getIdentity(token);
    } catch (err) {
      options.onError?.(err);
      return message(req, res, 502, 'GitHub authentication failed');
    }

    const result = checkDomain(config, identity);
    if (!result.ok) return message(req, res, 403, result.reason);

    const user = {
      id: identity.id,
      login: identity.login,
      name: identity.name,
      avatarUrl: identity.avatarUrl,
      email: result.email,
    };
    await config.onLogin?.(user);
    appendSetCookie(res, serializeCookie(cookieName, seal({ type: 'session', ...user }, secret, maxAge), {
      maxAge, path: '/', secure, sameSite,
    }));
    redirect(res, safeReturnTo(saved.returnTo, config.routes.afterLogin));
  }

  function handleLogout(req, res) {
    appendSetCookie(res, serializeCookie(cookieName, '', { maxAge: 0, path: '/', secure, sameSite }));
    if (wantsJson(req)) return sendJson(res, 200, { message: 'Signed out' });
    redirect(res, config.routes.afterLogout);
  }

  async function handlePasswordReset(req, res) {
    const pr = config.passwordReset;
    if (!pr.enabled) return message(req, res, 404, 'Password reset is disabled');
    if (pr.mode === 'github') return redirect(res, pr.resetUrl);

    if (req.method === 'GET') {
      return send(res, 200, page('Reset your password',
        `<form method="post" action="${escapeHtml(routes.passwordReset)}">` +
        '<label>E-mail <input type="email" name="email" required></label> ' +
        '<button type="submit">Send reset link</button></form>'));
    }
    const body = await readBody(req);
    await passwordReset.requestReset(body.email);
    return message(req, res, 202, 'If the address is registered, a reset link has been sent.');
  }

  async function handlePasswordResetConfirm(req, res, url) {
    const pr = config.passwordReset;
    if (!pr.enabled || pr.mode !== 'custom') return message(req, res, 404, 'Password reset is not available');

    if (req.method === 'GET') {
      const token = url.searchParams.get('token') || '';
      return send(res, 200, page('Choose a new password',
        `<form method="post" action="${escapeHtml(routes.passwordResetConfirm)}">` +
        `<input type="hidden" name="token" value="${escapeHtml(token)}">` +
        `<label>New password <input type="password" name="password" minlength="${pr.minPasswordLength}" required></label> ` +
        '<button type="submit">Reset password</button></form>'));
    }
    const body = await readBody(req);
    const result = await passwordReset.confirmReset(body.token, body.password);
    if (!result.ok) return message(req, res, 400, result.error);
    return message(req, res, 200, 'Your password has been reset.');
  }

  /**
   * Framework-agnostic request handler. Resolves `true` when the response has been sent
   * (auth route or access denied) and `false` when the request should continue.
   */
  async function handle(req, res) {
    const url = new URL(req.originalUrl || req.url, 'http://localhost');
    const { pathname } = url;
    const method = req.method;

    try {
      if (pathname === routes.login && method === 'GET') return (await handleLogin(req, res, url), true);
      if (pathname === routes.callback && method === 'GET') return (await handleCallback(req, res, url), true);
      if (pathname === routes.logout && (method === 'GET' || method === 'POST')) return (handleLogout(req, res), true);
      if (pathname === routes.me && method === 'GET') {
        const user = attach(req);
        if (!user) sendJson(res, 401, { message: 'Authentication required' });
        else sendJson(res, 200, describe(user));
        return true;
      }
      if (pathname === routes.passwordReset && (method === 'GET' || method === 'POST')) {
        return (await handlePasswordReset(req, res), true);
      }
      if (pathname === routes.passwordResetConfirm && (method === 'GET' || method === 'POST')) {
        return (await handlePasswordResetConfirm(req, res, url), true);
      }
    } catch (err) {
      if (err.status) return (message(req, res, err.status, err.message), true);
      throw err;
    }

    const user = attach(req);
    if (config.enforcePages && !permissions.canAccessPage(user, pathname)) {
      deny(req, res, user, pathname + url.search);
      return true;
    }
    return false;
  }

  /** Connect / Express style middleware: `app.use(auth.middleware())`. */
  function middleware() {
    return (req, res, next) => {
      handle(req, res).then((done) => (done ? undefined : next()), next);
    };
  }

  function guard(check) {
    return (req, res, next) => {
      const user = req.auth ? req.auth.user : attach(req);
      if (!user || !check(user)) return deny(req, res, user, req.originalUrl || req.url);
      next();
    };
  }

  return {
    config,
    routes,
    permissions,
    passwordReset,
    handle,
    middleware,
    getUser,
    describe,
    hasFeature: permissions.hasFeature,
    canAccessPage: permissions.canAccessPage,
    getRoles: permissions.getRoles,
    /** Route guard: user must be signed in. */
    requireAuth: () => guard(() => true),
    /** Route guard: user must have the feature turned on. */
    requireFeature: (name) => guard((user) => permissions.hasFeature(user, name)),
    /** Route guard: user must have at least one of the roles. */
    requireRole: (...roles) => guard((user) => permissions.getRoles(user).some((r) => roles.flat().includes(r))),
  };
}
