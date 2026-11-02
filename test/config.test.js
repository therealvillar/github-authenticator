import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { normalizeConfig, loadConfig, substituteEnv, defineConfig } from '../src/index.js';
import { baseConfig } from './helpers.js';

test('applies defaults and normalises values', () => {
  const c = normalizeConfig(baseConfig({ domain: { allowed: '@Example.COM' }, routes: { basePath: 'login/' } }));
  assert.deepEqual(c.domain.allowed, ['example.com']);
  assert.equal(c.routes.basePath, '/login');
  assert.equal(c.session.cookieName, 'gh_auth');
  assert.ok(c.users.octocat, 'user keys are lower-cased');
  assert.equal(c.passwordReset.mode, 'github');
  assert.equal(c.passwordReset.resetUrl, 'https://github.com/password_reset');
});

test('normalising twice is idempotent', () => {
  const once = normalizeConfig(baseConfig());
  assert.deepEqual(normalizeConfig(once).routes, once.routes);
});

test('reports all validation errors', () => {
  assert.throws(
    () => normalizeConfig({ session: { secret: 'short' }, defaultRoles: ['ghost'], passwordReset: { mode: 'custom' } }),
    (err) =>
      /clientId/.test(err.message) &&
      /clientSecret/.test(err.message) &&
      /session.secret/.test(err.message) &&
      /unknown role 'ghost'/.test(err.message) &&
      /sendResetEmail/.test(err.message),
  );
});

test('defineConfig is an identity helper', () => {
  const c = {};
  assert.equal(defineConfig(c), c);
});

test('substituteEnv replaces placeholders recursively', () => {
  assert.deepEqual(substituteEnv({ a: '${A}', b: ['x-${B}'], c: 1 }, { A: '1', B: '2' }), { a: '1', b: ['x-2'], c: 1 });
});

test('loadConfig reads JSON (with env) and JS configs', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gha-'));
  const json = baseConfig();
  json.github.clientSecret = '${GH_SECRET}';
  await writeFile(path.join(dir, 'authenticator.config.json'), JSON.stringify(json));
  const fromJson = await loadConfig(undefined, { cwd: dir, env: { GH_SECRET: 'from-env' } });
  assert.equal(fromJson.github.clientSecret, 'from-env');

  await writeFile(
    path.join(dir, 'custom.mjs'),
    `export default (env) => (${JSON.stringify(baseConfig())});`,
  );
  const fromJs = await loadConfig('custom.mjs', { cwd: dir, env: {} });
  assert.equal(fromJs.github.clientId, 'cid');

  await assert.rejects(loadConfig(undefined, { cwd: tmpdir() + '/does-not-exist', env: {} }), /No configuration file/);
});
