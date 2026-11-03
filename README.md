# github-authenticator

Reusable, configuration-driven **GitHub OAuth authentication flow** for Node.js projects.
Drop it into any project, describe your rules in a single config file, and get:

- 🔐 GitHub OAuth login / callback / logout with signed, HttpOnly session cookies and CSRF-safe `state`
- 🏢 **Required domain** – users must own a verified GitHub e-mail on your domain(s) (and/or have a username suffix, e.g. EMU `_acme`)
- 🎚️ **Feature toggles** – turn functions on/off globally, per role, or per user
- 🚪 **Page permissions** – public / authenticated / role / user / feature based rules with `*` and `**` globs
- 🔁 **User-requested password reset** – redirect to GitHub, or a token-based flow with your own hooks
- 🧩 Works with Express/Connect (`app.use(auth.middleware())`) or plain `node:http` – zero runtime dependencies

## Install

```bash
npm install github:therealvillar/github-authenticator
```

Requires Node.js 18+.

## Quick start

1. Create a GitHub OAuth App (*Settings → Developer settings → OAuth Apps*) with callback URL
   `https://your-app.example.com/auth/callback`.
2. Copy [`authenticator.config.example.js`](./authenticator.config.example.js) to `authenticator.config.js`
   in your project and edit it.
3. Set the environment variables `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL`, `SESSION_SECRET`.
4. Wire it in:

```js
import express from 'express';
import { createAuthenticator, loadConfig } from 'github-authenticator';

const auth = createAuthenticator(await loadConfig()); // finds authenticator.config.{js,mjs,json}
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(auth.middleware()); // mounts /auth/* routes, enforces page rules, sets req.user / req.auth

app.get('/api/export', auth.requireFeature('export'), handler);
app.get('/admin', auth.requireRole('admin'), handler);
```

Plain `node:http`:

```js
http.createServer(async (req, res) => {
  if (await auth.handle(req, res)) return; // auth route handled or access denied
  // req.user, req.auth.hasFeature('x'), req.auth.canAccess('/path') are available here
});
```

See [`examples/`](./examples) for complete apps.

## Routes

All routes live under `routes.basePath` (default `/auth`).

| Route | Description |
| --- | --- |
| `GET /auth/login?returnTo=/path` | Starts the GitHub OAuth flow (`returnTo` must be a relative path) |
| `GET /auth/callback` | OAuth callback – validates `state`, domain and allow-list, creates the session |
| `GET\|POST /auth/logout` | Clears the session |
| `GET /auth/me` | JSON: `{ user, roles, features }` for the signed-in user |
| `GET\|POST /auth/password-reset` | Password reset request (see below) |
| `GET\|POST /auth/password-reset/confirm` | Custom mode only – set a new password with a token |

## Configuration

`loadConfig(file?)` loads `authenticator.config.js`, `.mjs` or `.json` from the working directory (or the
path in `GH_AUTH_CONFIG`). JS configs may export an object or a (async) function receiving `process.env`.
JSON configs support `${ENV_VAR}` placeholders. You can also pass an object straight to `createAuthenticator`.
Invalid configs throw an error listing every problem.

```js
import { defineConfig } from 'github-authenticator';

export default defineConfig({
  github: { clientId, clientSecret, callbackUrl, scopes: ['read:user', 'user:email'] },
  session: { secret, cookieName: 'gh_auth', maxAge: 28800, secure: true, sameSite: 'Lax' },
  routes: { basePath: '/auth', afterLogin: '/', afterLogout: '/' },

  domain: { allowed: ['example.com'], usernameSuffix: undefined },
  allowedUsers: [],                 // optional login allow-list

  defaultRoles: ['member'],
  roles: {
    admin: { features: ['*'], pages: ['*'] },
    member: { features: ['view-calendar'] },
  },
  features: {
    'view-calendar': { default: true },
    'legacy-reports': { enabled: false },
  },
  users: {
    octocat: { roles: ['admin'] },
    hubot: { features: { export: false }, pages: { allow: ['/reports/**'], deny: ['/settings/**'] } },
  },
  pages: [
    { path: '/', public: true },
    { path: '/admin/**', roles: ['admin'] },
    { path: '/events/edit/*', features: ['edit-events'] },
  ],
  defaultPageAccess: 'authenticated',
  enforcePages: true,

  passwordReset: { enabled: true, mode: 'github' },
  onLogin: async (user) => {},      // optional hook
});
```

### Required domain

- `domain.allowed` – the user must have at least one **verified** GitHub e-mail on one of these domains
  (exact match; sub-domains must be listed explicitly). The matching address becomes `user.email`.
- `domain.usernameSuffix` – the GitHub login must end with this suffix (useful for Enterprise Managed Users).
- `allowedUsers` – optional list of permitted GitHub logins.

These checks are re-evaluated on every request, so removing a user from the config revokes access immediately.

### Feature toggles

`auth.hasFeature(user, name)` / `req.auth.hasFeature(name)` resolves in this order:

1. `features.<name>.enabled === false` → **off for everyone** (kill switch)
2. `users.<login>.features.<name>` is `true`/`false` → per-user override
3. any of the user's roles lists the feature (or `'*'`) → on
4. `features.<name>.default` → fallback (`features.<name>.public` enables it for anonymous visitors)

### Page permissions

`auth.canAccessPage(user, path)` / `req.auth.canAccess(path)`:

1. first matching `pages` rule has `public: true` → allowed for everyone
2. anonymous users are denied (redirected to login, or `401` for JSON requests)
3. `users.<login>.pages.deny` match → denied; `users.<login>.pages.allow` match → allowed
4. a role's `pages` list matches (`'*'` = everything) → allowed
5. first matching rule: user must have one of `roles` **or** be in `users`, and must have every feature in `features`
6. no matching rule → `defaultPageAccess` (`'authenticated'`, `'public'` or `'deny'`)

Patterns: `*` matches one path segment, `**` any number (`/admin/**` also matches `/admin`). Matching is
case-insensitive and paths are checked both raw and percent-decoded (with duplicate/trailing slashes removed);
access must be granted for every variant, so rules cannot be bypassed with `/ADMIN` or `/%61dmin`.
Set `enforcePages: false` to only populate `req.auth` and enforce access yourself with the route guards
`requireAuth()`, `requireRole(...roles)` and `requireFeature(name)`.

### Password reset

- **`mode: 'github'`** (default) – GitHub owns the password, so `/auth/password-reset` redirects to
  `passwordReset.resetUrl` (default `https://github.com/password_reset`, or your GHES equivalent).
- **`mode: 'custom'`** – for apps with their own credentials. `/auth/password-reset` shows a form / accepts
  `POST { email }`; a single-use token (stored hashed, expiring after `tokenTtl` seconds) is passed to your
  `sendResetEmail({ email, token, resetLink, expiresIn })` hook. The user opens `resetLink`, posts
  `{ token, password }` to `/auth/password-reset/confirm`, and `onPasswordReset({ email, password })` is called.
  Responses never reveal whether an address exists, and addresses outside `domain.allowed` are ignored.
  Provide `passwordReset.store` (`get/set/delete`, async) for multi-instance deployments; the default
  `MemoryStore` is per-process. Consider rate-limiting the request endpoint in production.

## API

| Export | Description |
| --- | --- |
| `createAuthenticator(config, { fetch?, onError? })` | Returns `{ middleware, handle, getUser, describe, hasFeature, canAccessPage, getRoles, requireAuth, requireRole, requireFeature, routes, config, permissions, passwordReset }` |
| `loadConfig(file?, { cwd?, env? })` | Loads and validates a config file |
| `defineConfig(config)` | Identity helper for editor autocomplete |
| `normalizeConfig(config)` | Applies defaults and validates |
| `createPermissions(config)`, `checkDomain(config, identity)`, `matchPath(pattern, path)` | Lower-level helpers |

## Development

```bash
npm test
```
