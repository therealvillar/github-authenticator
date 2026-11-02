import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPermissions, normalizeConfig, matchPath } from '../src/index.js';
import { baseConfig } from './helpers.js';

const perms = (o) => createPermissions(normalizeConfig(baseConfig(o)));
const admin = { login: 'OCTOCAT' };
const hubot = { login: 'hubot' };
const member = { login: 'mona' };

test('matchPath supports * and **', () => {
  assert.ok(matchPath('/admin/**', '/admin'));
  assert.ok(matchPath('/admin/**', '/admin/a/b'));
  assert.ok(!matchPath('/admin/**', '/administrator'));
  assert.ok(matchPath('/edit/*', '/edit/1'));
  assert.ok(!matchPath('/edit/*', '/edit/1/2'));
  assert.ok(matchPath('/file.txt', '/file.txt'));
  assert.ok(!matchPath('/file.txt', '/fileXtxt'));
});

test('roles include defaults and per-user roles', () => {
  const p = perms();
  assert.deepEqual(p.getRoles(admin), ['member', 'admin']);
  assert.deepEqual(p.getRoles(member), ['member']);
  assert.deepEqual(p.getRoles(null), []);
});

test('feature resolution: kill switch, user override, role, default', () => {
  const p = perms();
  assert.equal(p.hasFeature(admin, 'legacy'), false, 'globally disabled beats wildcard');
  assert.equal(p.hasFeature(admin, 'export'), true);
  assert.equal(p.hasFeature(hubot, 'export'), false, 'per-user off overrides role');
  assert.equal(p.hasFeature(hubot, 'secret'), true, 'per-user on');
  assert.equal(p.hasFeature(hubot, 'edit'), true, 'via role');
  assert.equal(p.hasFeature(member, 'edit'), false);
  assert.equal(p.hasFeature(member, 'view'), true);
  assert.equal(p.hasFeature(member, 'beta'), true, 'default on');
  assert.equal(p.hasFeature(null, 'beta'), false);
  assert.equal(p.hasFeature(null, 'banner'), true, 'public feature');
  const all = p.getFeatures(hubot);
  assert.equal(all.secret, true);
  assert.equal(all.export, false);
});

test('page access rules', () => {
  const p = perms();
  assert.equal(p.canAccessPage(null, '/'), true);
  assert.equal(p.canAccessPage(null, '/public/x'), true);
  assert.equal(p.canAccessPage(null, '/dashboard'), false);
  assert.equal(p.canAccessPage(member, '/dashboard'), true, 'default authenticated');
  assert.equal(p.canAccessPage(member, '/admin'), false);
  assert.equal(p.canAccessPage(admin, '/admin/users'), true);
  assert.equal(p.canAccessPage(member, '/edit/1'), false);
  assert.equal(p.canAccessPage(hubot, '/edit/1'), true, 'feature requirement');
  assert.equal(p.canAccessPage(hubot, '/reports/q1'), true, 'per-user allow');
  assert.equal(p.canAccessPage(member, '/reports/q1'), false);
  assert.equal(p.canAccessPage({ login: 'someone' }, '/reports/q1'), true, 'rule users list');
  assert.equal(p.canAccessPage(hubot, '/settings/profile'), false, 'per-user deny');
});

test('defaultPageAccess deny / public', () => {
  assert.equal(perms({ defaultPageAccess: 'deny' }).canAccessPage(member, '/other'), false);
  assert.equal(perms({ defaultPageAccess: 'deny' }).canAccessPage(admin, '/other'), true, 'admin role has *');
  assert.equal(perms({ defaultPageAccess: 'public' }).canAccessPage(null, '/other'), true);
});

test('page rules cannot be bypassed with case, encoding or extra slashes', () => {
  const p = perms();
  for (const path of ['/ADMIN/x', '/Admin', '/%61dmin/x', '//admin//x', '/admin/', '/%2561dmin']) {
    assert.equal(p.canAccessPage(member, path), path === '/%2561dmin', path);
  }
  assert.equal(p.canAccessPage(hubot, '/edit/1/'), true, 'trailing slash still matches /edit/*');
  assert.equal(p.canAccessPage(null, '/PUBLIC/x'), true);
});
