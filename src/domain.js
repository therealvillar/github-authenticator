/**
 * Checks a GitHub identity against the configured domain / allow-list requirements.
 *
 * @param {object} config normalised config
 * @param {{ login: string, emails?: Array<{ email: string, verified?: boolean, primary?: boolean }> }} identity
 * @returns {{ ok: true, email?: string } | { ok: false, reason: string }}
 */
export function checkDomain(config, { login, emails = [] }) {
  const lcLogin = String(login || '').toLowerCase();
  const { allowed, usernameSuffix } = config.domain;

  if (config.allowedUsers.length && !config.allowedUsers.includes(lcLogin)) {
    return { ok: false, reason: `User '${login}' is not in the allowed users list` };
  }

  if (usernameSuffix && !lcLogin.endsWith(String(usernameSuffix).toLowerCase())) {
    return { ok: false, reason: `Username must end with '${usernameSuffix}'` };
  }

  if (!allowed.length) {
    const primary = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified);
    return { ok: true, email: primary?.email };
  }

  const matching = emails
    .filter((e) => e.verified && isEmailInDomains(e.email, allowed))
    .sort((a, b) => Number(Boolean(b.primary)) - Number(Boolean(a.primary)));

  if (!matching.length) {
    return {
      ok: false,
      reason: `A verified e-mail address on ${allowed.map((d) => `@${d}`).join(' or ')} is required`,
    };
  }
  return { ok: true, email: matching[0].email };
}

/** True when the e-mail's domain equals one of `domains` (sub-domains are not accepted). */
export function isEmailInDomains(email, domains) {
  const at = String(email || '').lastIndexOf('@');
  if (at < 1) return false;
  const domain = String(email).slice(at + 1).toLowerCase();
  return domains.includes(domain);
}
