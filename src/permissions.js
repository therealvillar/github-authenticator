const regexCache = new Map();

/**
 * Converts a path pattern to a RegExp.
 *  - `*`  matches a single path segment
 *  - `**` matches any number of segments (including none)
 *  - patterns are matched case-insensitively against the full path (query strings are ignored)
 */
export function patternToRegExp(pattern) {
  if (regexCache.has(pattern)) return regexCache.get(pattern);
  let src = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '*' && pattern[i + 1] === '*') {
      // '/**' at a segment boundary also matches the bare parent path.
      if (src.endsWith('/')) {
        src = src.slice(0, -1) + '(?:/.*)?';
      } else {
        src += '.*';
      }
      i++;
    } else if (ch === '*') {
      src += '[^/]*';
    } else {
      src += ch.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  const re = new RegExp(`^${src}$`, 'i');
  regexCache.set(pattern, re);
  return re;
}

export function matchPath(pattern, pathname) {
  return patternToRegExp(pattern).test(pathname);
}

/**
 * Returns the path variants a router could resolve a request path to: the raw path and the
 * percent-decoded path, both with duplicate / trailing slashes removed. Access must be granted for all of them.
 */
export function pathVariants(pathname) {
  const clean = (p) => {
    const segments = String(p || '/').split('?')[0].split('/').filter(Boolean);
    return `/${segments.join('/')}`;
  };
  const variants = new Set([clean(pathname)]);
  try {
    variants.add(clean(decodeURIComponent(pathname)));
  } catch {
    // Malformed escapes: the raw variant alone is evaluated.
  }
  return [...variants];
}

const toList = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
const anyMatch = (patterns, pathname) => toList(patterns).some((p) => matchPath(p, pathname));

/**
 * Builds permission helpers from a normalised config.
 * All lookups are evaluated at call time so configuration changes take effect immediately.
 */
export function createPermissions(config) {
  const userEntry = (user) => (user ? config.users[String(user.login).toLowerCase()] || {} : {});

  function getRoles(user) {
    if (!user) return [];
    const entry = userEntry(user);
    return [...new Set([...(config.defaultRoles || []), ...toList(entry.roles)])];
  }

  function roleGrantsFeature(roles, feature) {
    return roles.some((role) => {
      const features = toList(config.roles[role]?.features);
      return features.includes('*') || features.includes(feature);
    });
  }

  /**
   * Resolution order:
   *  1. feature globally disabled (`features.x.enabled === false`)      -> off for everyone
   *  2. per-user override (`users.<login>.features.x = true | false`)    -> wins
   *  3. any of the user's roles lists the feature (or '*')               -> on
   *  4. feature default (`features.x.default`)                           -> fallback
   */
  function hasFeature(user, feature) {
    const def = config.features[feature];
    if (def && def.enabled === false) return false;
    if (!user) return Boolean(def?.public);
    const override = userEntry(user).features?.[feature];
    if (typeof override === 'boolean') return override;
    if (roleGrantsFeature(getRoles(user), feature)) return true;
    return Boolean(def?.default);
  }

  function getFeatures(user) {
    const names = new Set(Object.keys(config.features));
    for (const role of Object.values(config.roles)) {
      for (const f of toList(role?.features)) if (f !== '*') names.add(f);
    }
    for (const entry of Object.values(config.users)) {
      for (const f of Object.keys(entry?.features || {})) names.add(f);
    }
    return Object.fromEntries([...names].sort().map((name) => [name, hasFeature(user, name)]));
  }

  function findPageRule(pathname) {
    return config.pages.find((rule) => matchPath(rule.path, pathname));
  }

  /**
   * Resolution order:
   *  1. first matching rule with `public: true`                         -> allowed for everyone
   *  2. not signed in                                                   -> denied
   *  3. per-user `pages.deny` match                                      -> denied
   *  4. per-user `pages.allow` match                                     -> allowed
   *  5. role `pages` list match ('*' / '/**' = everything)               -> allowed
   *  6. first matching rule: must satisfy `roles`, `users` and `features` -> allowed / denied
   *  7. no rule: `defaultPageAccess`
   */
  function canAccessPage(user, pathname) {
    return pathVariants(pathname).every((p) => canAccessNormalizedPage(user, p));
  }

  function canAccessNormalizedPage(user, pathname) {
    const rule = findPageRule(pathname);
    if (rule?.public) return true;
    if (!rule && config.defaultPageAccess === 'public') return true;
    if (!user) return false;

    const entry = userEntry(user);
    if (anyMatch(entry.pages?.deny, pathname)) return false;
    if (anyMatch(entry.pages?.allow, pathname)) return true;

    const roles = getRoles(user);
    const rolePages = roles.flatMap((r) => toList(config.roles[r]?.pages));
    if (rolePages.includes('*') || anyMatch(rolePages, pathname)) return true;

    if (!rule) return config.defaultPageAccess === 'authenticated';

    const login = String(user.login).toLowerCase();
    const ruleRoles = toList(rule.roles);
    const ruleUsers = toList(rule.users).map((u) => String(u).toLowerCase());
    const ruleFeatures = toList(rule.features);

    if (ruleRoles.length || ruleUsers.length) {
      const allowed = ruleRoles.some((r) => roles.includes(r)) || ruleUsers.includes(login);
      if (!allowed) return false;
    }
    return ruleFeatures.every((f) => hasFeature(user, f));
  }

  return { getRoles, hasFeature, getFeatures, canAccessPage, findPageRule };
}
