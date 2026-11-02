export const SECRET = 'x'.repeat(40);

export function baseConfig(overrides = {}) {
  return {
    github: { clientId: 'cid', clientSecret: 'csecret', callbackUrl: 'https://app.test/auth/callback' },
    session: { secret: SECRET, secure: false },
    domain: { allowed: ['example.com'] },
    defaultRoles: ['member'],
    roles: {
      admin: { features: ['*'], pages: ['*'] },
      editor: { features: ['edit', 'export'] },
      member: { features: ['view'] },
    },
    features: {
      view: {},
      edit: {},
      export: {},
      beta: { default: true },
      legacy: { enabled: false },
      banner: { public: true },
    },
    users: {
      Octocat: { roles: ['admin'] },
      hubot: {
        roles: ['editor'],
        features: { export: false, secret: true },
        pages: { allow: ['/reports/**'], deny: ['/settings/**'] },
      },
    },
    pages: [
      { path: '/', public: true },
      { path: '/public/**', public: true },
      { path: '/admin/**', roles: ['admin'] },
      { path: '/edit/*', features: ['edit'] },
      { path: '/reports/**', users: ['someone'] },
    ],
    ...overrides,
  };
}
