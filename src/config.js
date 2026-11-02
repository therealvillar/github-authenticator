import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const DEFAULT_CONFIG_FILES = [
  'authenticator.config.js',
  'authenticator.config.mjs',
  'authenticator.config.json',
];

const DEFAULTS = {
  github: {
    clientId: undefined,
    clientSecret: undefined,
    callbackUrl: undefined,
    scopes: ['read:user', 'user:email'],
    baseUrl: 'https://github.com',
    apiUrl: 'https://api.github.com',
  },
  session: {
    secret: undefined,
    cookieName: 'gh_auth',
    maxAge: 8 * 60 * 60, // seconds
    secure: true,
    sameSite: 'Lax',
  },
  routes: {
    basePath: '/auth',
    afterLogin: '/',
    afterLogout: '/',
  },
  domain: {
    // Verified e-mail domains a user must have one of, e.g. ['example.com'].
    allowed: [],
    // Optional GitHub username suffix, e.g. '_acme' for Enterprise Managed Users.
    usernameSuffix: undefined,
  },
  // Optional explicit allow-list of GitHub logins. Empty = everyone who passes the domain check.
  allowedUsers: [],
  defaultRoles: [],
  roles: {},
  users: {},
  features: {},
  pages: [],
  // What to do with paths that match no page rule: 'authenticated' | 'public' | 'deny'.
  defaultPageAccess: 'authenticated',
  // When true, the middleware blocks requests to pages the user can't access.
  enforcePages: true,
  // Optional async hook called with the user after a successful login (e.g. audit logging).
  onLogin: undefined,
  passwordReset: {
    enabled: true,
    // 'github': send the user to GitHub's password reset page.
    // 'custom': token based reset handled by your own hooks (sendResetEmail / onPasswordReset).
    mode: 'github',
    tokenTtl: 60 * 60, // seconds
    minPasswordLength: 12,
    // GitHub mode: where users are sent (defaults to <github.baseUrl>/password_reset).
    resetUrl: undefined,
    // Custom mode: page that receives ?token=... (defaults to <callback origin><basePath>/password-reset/confirm).
    resetPageUrl: undefined,
    sendResetEmail: undefined,
    onPasswordReset: undefined,
    store: undefined,
  },
};

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function merge(defaults, value) {
  if (!isPlainObject(defaults) || !isPlainObject(value)) {
    return value === undefined ? defaults : value;
  }
  const out = { ...defaults };
  for (const [key, v] of Object.entries(value)) {
    out[key] = key in defaults ? merge(defaults[key], v) : v;
  }
  return out;
}

const lowerKeys = (obj) =>
  Object.fromEntries(Object.entries(obj || {}).map(([k, v]) => [k.toLowerCase(), v]));

/**
 * Identity helper that gives editors autocomplete / documentation for the config shape.
 * @param {object} config
 */
export function defineConfig(config) {
  return config;
}

/**
 * Applies defaults, normalises and validates a configuration object.
 * Throws an Error listing every problem found.
 */
export function normalizeConfig(input = {}) {
  const config = merge(DEFAULTS, input);
  const errors = [];

  if (!config.github.clientId) errors.push('github.clientId is required');
  if (!config.github.clientSecret) errors.push('github.clientSecret is required');
  if (!config.session.secret || String(config.session.secret).length < 32) {
    errors.push('session.secret is required and must be at least 32 characters');
  }
  if (!Array.isArray(config.github.scopes)) errors.push('github.scopes must be an array');

  if (typeof config.domain.allowed === 'string') config.domain.allowed = [config.domain.allowed];
  if (!Array.isArray(config.domain.allowed)) errors.push('domain.allowed must be an array of domains');
  else config.domain.allowed = config.domain.allowed.map((d) => String(d).toLowerCase().replace(/^@/, ''));

  if (!Array.isArray(config.allowedUsers)) errors.push('allowedUsers must be an array');
  else config.allowedUsers = config.allowedUsers.map((u) => String(u).toLowerCase());

  if (!Array.isArray(config.defaultRoles)) errors.push('defaultRoles must be an array');
  if (!isPlainObject(config.roles)) errors.push('roles must be an object');
  if (!isPlainObject(config.users)) errors.push('users must be an object');
  if (!isPlainObject(config.features)) errors.push('features must be an object');
  if (!Array.isArray(config.pages)) errors.push('pages must be an array of rules');

  if (!['authenticated', 'public', 'deny'].includes(config.defaultPageAccess)) {
    errors.push("defaultPageAccess must be 'authenticated', 'public' or 'deny'");
  }

  if (Array.isArray(config.defaultRoles) && isPlainObject(config.roles)) {
    for (const role of config.defaultRoles) {
      if (!config.roles[role]) errors.push(`defaultRoles references unknown role '${role}'`);
    }
  }
  if (isPlainObject(config.users) && isPlainObject(config.roles)) {
    for (const [login, user] of Object.entries(config.users)) {
      for (const role of user?.roles || []) {
        if (!config.roles[role]) errors.push(`users.${login} references unknown role '${role}'`);
      }
    }
  }
  if (Array.isArray(config.pages)) {
    config.pages.forEach((rule, i) => {
      if (!rule || typeof rule.path !== 'string') errors.push(`pages[${i}].path must be a string`);
    });
  }

  const pr = config.passwordReset;
  if (pr.enabled) {
    if (!['github', 'custom'].includes(pr.mode)) {
      errors.push("passwordReset.mode must be 'github' or 'custom'");
    } else if (pr.mode === 'custom') {
      if (typeof pr.sendResetEmail !== 'function') {
        errors.push("passwordReset.sendResetEmail must be a function when mode is 'custom'");
      }
      if (typeof pr.onPasswordReset !== 'function') {
        errors.push("passwordReset.onPasswordReset must be a function when mode is 'custom'");
      }
    }
  }

  if (errors.length) {
    throw new Error(`Invalid github-authenticator configuration:\n  - ${errors.join('\n  - ')}`);
  }

  config.users = lowerKeys(config.users);
  config.routes.basePath = '/' + config.routes.basePath.replace(/^\/+|\/+$/g, '');
  if (!pr.resetUrl) pr.resetUrl = `${config.github.baseUrl.replace(/\/$/, '')}/password_reset`;
  return config;
}

/** Replaces ${VAR_NAME} placeholders in JSON configs with environment variables. */
export function substituteEnv(value, env = process.env) {
  if (typeof value === 'string') {
    return value.replace(/\$\{([A-Z0-9_]+)\}/gi, (_, name) => env[name] ?? '');
  }
  if (Array.isArray(value)) return value.map((v) => substituteEnv(v, env));
  if (isPlainObject(value)) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substituteEnv(v, env)]));
  }
  return value;
}

/**
 * Loads a configuration file (.js / .mjs default export, or .json with ${ENV} placeholders).
 * When no path is given, GH_AUTH_CONFIG or the default file names in `cwd` are used.
 */
export async function loadConfig(file, { cwd = process.cwd(), env = process.env } = {}) {
  let resolved;
  if (file || env.GH_AUTH_CONFIG) {
    resolved = path.resolve(cwd, file || env.GH_AUTH_CONFIG);
  } else {
    resolved = DEFAULT_CONFIG_FILES.map((f) => path.resolve(cwd, f)).find((f) => existsSync(f));
    if (!resolved) {
      throw new Error(`No configuration file found. Create one of: ${DEFAULT_CONFIG_FILES.join(', ')}`);
    }
  }

  let raw;
  if (resolved.endsWith('.json')) {
    raw = substituteEnv(JSON.parse(await readFile(resolved, 'utf8')), env);
  } else {
    const mod = await import(pathToFileURL(resolved).href);
    raw = mod.default ?? mod.config;
    if (typeof raw === 'function') raw = await raw(env);
  }
  return normalizeConfig(raw);
}
