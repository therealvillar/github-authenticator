import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkDomain, normalizeConfig, seal, unseal, parseCookies, serializeCookie } from '../src/index.js';
import { baseConfig, SECRET } from './helpers.js';

test('requires a verified e-mail on an allowed domain', () => {
  const c = normalizeConfig(baseConfig());
  assert.equal(checkDomain(c, { login: 'a', emails: [{ email: 'a@example.com', verified: false }] }).ok, false);
  assert.equal(checkDomain(c, { login: 'a', emails: [{ email: 'a@sub.example.com', verified: true }] }).ok, false);
  assert.equal(checkDomain(c, { login: 'a', emails: [{ email: 'a@evil.com', verified: true }] }).ok, false);
  const ok = checkDomain(c, {
    login: 'a',
    emails: [
      { email: 'a@gmail.com', verified: true, primary: true },
      { email: 'A@Example.com', verified: true },
    ],
  });
  assert.deepEqual(ok, { ok: true, email: 'A@Example.com' });
});

test('username suffix and allowed users', () => {
  const c = normalizeConfig(baseConfig({ domain: { allowed: [], usernameSuffix: '_acme' }, allowedUsers: ['Mona_ACME'] }));
  assert.equal(checkDomain(c, { login: 'mona' }).ok, false);
  assert.equal(checkDomain(c, { login: 'bob_acme' }).ok, false);
  assert.equal(checkDomain(c, { login: 'mona_acme' }).ok, true);
});

test('seal / unseal detects tampering and expiry', () => {
  const token = seal({ login: 'a' }, SECRET, 60);
  assert.equal(unseal(token, SECRET).login, 'a');
  assert.equal(unseal(token, 'y'.repeat(40)), null);
  assert.equal(unseal(token.slice(0, -2) + 'aa', SECRET), null);
  assert.equal(unseal(seal({ login: 'a' }, SECRET, -1), SECRET), null);
  assert.equal(unseal('garbage', SECRET), null);
});

test('cookie helpers', () => {
  assert.deepEqual(parseCookies('a=1; b=hello%20world; c'), { a: '1', b: 'hello world' });
  assert.equal(
    serializeCookie('n', 'v', { maxAge: 10, secure: true }),
    'n=v; Path=/; Max-Age=10; HttpOnly; Secure; SameSite=Lax',
  );
});
