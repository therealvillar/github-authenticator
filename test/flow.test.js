import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createAuthenticator } from '../src/index.js';
import { baseConfig } from './helpers.js';

let identity;
const sentEmails = [];
const passwords = {};

function fakeGitHub(url, init = {}) {
  const json = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
  if (url === 'https://github.com/login/oauth/access_token') {
    const body = new URLSearchParams(init.body);
    if (body.get('code') !== 'good-code' || body.get('client_secret') !== 'csecret') return json({ error: 'bad_verification_code' });
    return json({ access_token: 'tok' });
  }
  assert.equal(init.headers.Authorization, 'Bearer ' + 'tok');
  if (url === 'https://api.github.com/user') return json(identity.user);
  if (url === 'https://api.github.com/user/emails') return json(identity.emails);
  return json({}, 404);
}

function makeServer(config) {
  const auth = createAuthenticator(config, { fetch: fakeGitHub });
  const server = http.createServer(async (req, res) => {
    if (await auth.handle(req, res)) return;
    res.end(JSON.stringify({ path: req.url, user: req.user?.login ?? null, export: req.auth.hasFeature('export') }));
  });
  return { auth, server };
}

let base, server, auth;
before(async () => {
  ({ auth, server } = makeServer(
    baseConfig({
      passwordReset: {
        mode: 'custom',
        sendResetEmail: async (m) => sentEmails.push(m),
        onPasswordReset: async ({ email, password }) => (passwords[email] = password),
      },
    }),
  ));
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const get = (p, headers = {}) => fetch(base + p, { redirect: 'manual', headers });
const cookiesFrom = (res) => res.headers.getSetCookie().map((c) => c.split(';')[0]).filter((c) => !c.endsWith('=')).join('; ');

async function login(user, emails, returnTo = '/dashboard') {
  identity = { user, emails };
  const start = await get(`/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  assert.equal(start.status, 302);
  const authorize = new URL(start.headers.get('location'));
  assert.equal(authorize.origin + authorize.pathname, 'https://github.com/login/oauth/authorize');
  assert.equal(authorize.searchParams.get('client_id'), 'cid');
  assert.equal(authorize.searchParams.get('redirect_uri'), 'https://app.test/auth/callback');
  const state = authorize.searchParams.get('state');
  return get(`/auth/callback?code=good-code&state=${state}`, { cookie: cookiesFrom(start) });
}

test('public pages are open, protected pages redirect to login', async () => {
  assert.equal((await get('/')).status, 200);
  const res = await get('/dashboard?x=1');
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/auth/login?returnTo=%2Fdashboard%3Fx%3D1');
  assert.equal((await get('/dashboard', { accept: 'application/json' })).status, 401);
});

test('full login flow for a user on the required domain', async () => {
  const res = await login({ id: 1, login: 'hubot', name: 'Hubot' }, [{ email: 'hubot@example.com', verified: true, primary: true }]);
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/dashboard');
  const cookie = cookiesFrom(res);
  assert.match(cookie, /^gh_auth=/);

  const page = await (await get('/dashboard', { cookie })).json();
  assert.deepEqual(page, { path: '/dashboard', user: 'hubot', export: false });

  const me = await (await get('/auth/me', { cookie })).json();
  assert.equal(me.user.email, 'hubot@example.com');
  assert.deepEqual(me.roles, ['member', 'editor']);
  assert.equal(me.features.edit, true);
  assert.equal(me.features.export, false);

  assert.equal((await get('/admin', { cookie })).status, 403);
  assert.equal((await get('/settings/profile', { cookie })).status, 403);

  const out = await get('/auth/logout', { cookie });
  assert.equal(out.status, 302);
  assert.match(out.headers.getSetCookie()[0], /^gh_auth=; .*Max-Age=0/);
});

test('rejects users without a verified e-mail on the domain', async () => {
  const res = await login({ id: 2, login: 'mallory' }, [{ email: 'm@evil.com', verified: true, primary: true }]);
  assert.equal(res.status, 403);
  assert.match(await res.text(), /@example\.com/);
});

test('rejects bad state and open redirects', async () => {
  assert.equal((await get('/auth/callback?code=good-code&state=nope')).status, 400);
  const res = await login({ id: 1, login: 'octocat' }, [{ email: 'o@example.com', verified: true }], '//evil.com');
  assert.equal(res.headers.get('location'), '/');
});

test('GitHub errors are reported without leaking details', async () => {
  identity = { user: { login: 'x' }, emails: [] };
  const start = await get('/auth/login');
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  const res = await get(`/auth/callback?code=bad&state=${state}`, { cookie: cookiesFrom(start) });
  assert.equal(res.status, 502);
});

test('custom password reset flow', async () => {
  const form = await get('/auth/password-reset');
  assert.equal(form.status, 200);
  assert.match(await form.text(), /<form/);

  const post = (p, body) =>
    fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

  assert.equal((await post('/auth/password-reset', { email: 'nobody@evil.com' })).status, 202);
  assert.equal(sentEmails.length, 0, 'emails outside the domain are ignored silently');

  assert.equal((await post('/auth/password-reset', { email: 'Mona@Example.com' })).status, 202);
  assert.equal(sentEmails.length, 1);
  const { email, token, resetLink } = sentEmails[0];
  assert.equal(email, 'mona@example.com');
  assert.equal(resetLink, `https://app.test/auth/password-reset/confirm?token=${token}`);

  const confirmPage = await (await get(`/auth/password-reset/confirm?token=${token}`)).text();
  assert.match(confirmPage, new RegExp(`value="${token}"`));

  assert.equal((await post('/auth/password-reset/confirm', { token, password: 'short' })).status, 400);
  assert.equal((await post('/auth/password-reset/confirm', { token, password: 'a-long-new-password' })).status, 200);
  assert.equal(passwords['mona@example.com'], 'a-long-new-password');
  assert.equal((await post('/auth/password-reset/confirm', { token, password: 'a-long-new-password' })).status, 400, 'single use');
});

test('github password reset mode redirects to GitHub', async () => {
  const { server: s } = makeServer(baseConfig());
  await new Promise((r) => s.listen(0, r));
  const res = await fetch(`http://127.0.0.1:${s.address().port}/auth/password-reset`, { redirect: 'manual' });
  s.close();
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://github.com/password_reset');
});

test('express-style middleware and route guards', async () => {
  const mw = auth.middleware();
  const res = { headers: {}, statusCode: 200, setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, getHeader(k) { return this.headers[k.toLowerCase()]; }, end() { this.ended = true; } };
  const req = { method: 'GET', url: '/', headers: {} };
  await new Promise((resolve) => mw(req, res, resolve));
  assert.equal(req.user, null);

  const guard = auth.requireFeature('export');
  const denied = { ...res, headers: {} };
  let nextCalled = false;
  guard({ method: 'GET', url: '/api', headers: { accept: 'application/json' } }, denied, () => (nextCalled = true));
  assert.equal(nextCalled, false);
  assert.equal(denied.statusCode, 401);
});
