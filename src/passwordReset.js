import { createHash, randomBytes } from 'node:crypto';
import { isEmailInDomains } from './domain.js';

/** Simple in-memory token store. Supply your own (Redis, DB, ...) with the same async interface for multi-instance deployments. */
export class MemoryStore {
  constructor() {
    this.map = new Map();
  }
  async get(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (entry.expires < Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }
  async set(key, value, ttlSeconds) {
    for (const [k, e] of this.map) if (e.expires < Date.now()) this.map.delete(k);
    this.map.set(key, { value, expires: Date.now() + ttlSeconds * 1000 });
  }
  async delete(key) {
    this.map.delete(key);
  }
}

const hashToken = (token) => createHash('sha256').update(String(token)).digest('hex');

function isValidEmail(email) {
  if (email.length > 254 || /\s/.test(email)) return false;
  const at = email.indexOf('@');
  if (at < 1 || at !== email.lastIndexOf('@')) return false;
  const domain = email.slice(at + 1);
  const dot = domain.lastIndexOf('.');
  return dot > 0 && dot < domain.length - 1;
}

/**
 * User-requested password reset.
 *
 * - mode 'github': GitHub owns the password, so users are redirected to GitHub's reset page.
 * - mode 'custom': a single-use, expiring token is generated and handed to `sendResetEmail`;
 *   `confirmReset` verifies it and calls `onPasswordReset` with the new password.
 */
export function createPasswordReset(config) {
  const opts = config.passwordReset;
  const store = opts.store || new MemoryStore();

  function resetPageUrl() {
    if (opts.resetPageUrl) return opts.resetPageUrl;
    if (config.github.callbackUrl) {
      return `${new URL(config.github.callbackUrl).origin}${config.routes.basePath}/password-reset/confirm`;
    }
    return `${config.routes.basePath}/password-reset/confirm`;
  }

  /** Always resolves without revealing whether the address is known. */
  async function requestReset(email) {
    if (!opts.enabled || opts.mode !== 'custom') return { sent: false };
    const normalized = String(email || '').trim().toLowerCase();
    if (!isValidEmail(normalized)) return { sent: false };
    if (config.domain.allowed.length && !isEmailInDomains(normalized, config.domain.allowed)) {
      return { sent: false };
    }
    const token = randomBytes(32).toString('base64url');
    await store.set(hashToken(token), { email: normalized }, opts.tokenTtl);
    const url = new URL(resetPageUrl(), 'http://placeholder');
    url.searchParams.set('token', token);
    const resetLink = opts.resetPageUrl || config.github.callbackUrl ? url.href : `${url.pathname}${url.search}`;
    await opts.sendResetEmail({ email: normalized, token, resetLink, expiresIn: opts.tokenTtl });
    return { sent: true };
  }

  async function confirmReset(token, password) {
    if (!opts.enabled || opts.mode !== 'custom') return { ok: false, error: 'Password reset is not available' };
    if (typeof password !== 'string' || password.length < opts.minPasswordLength) {
      return { ok: false, error: `Password must be at least ${opts.minPasswordLength} characters` };
    }
    const key = hashToken(token);
    const entry = token ? await store.get(key) : undefined;
    if (!entry) return { ok: false, error: 'Reset link is invalid or has expired' };
    await store.delete(key);
    await opts.onPasswordReset({ email: entry.email, password });
    return { ok: true };
  }

  return { requestReset, confirmReset, resetPageUrl, store };
}
