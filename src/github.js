/**
 * Minimal GitHub OAuth client. `fetchImpl` can be swapped for testing.
 */
export function createGitHubClient(githubConfig, fetchImpl = globalThis.fetch) {
  const baseUrl = githubConfig.baseUrl.replace(/\/$/, '');
  const apiUrl = githubConfig.apiUrl.replace(/\/$/, '');

  function authorizeUrl({ state, redirectUri }) {
    const params = new URLSearchParams({
      client_id: githubConfig.clientId,
      scope: githubConfig.scopes.join(' '),
      state,
      allow_signup: 'false',
    });
    if (redirectUri) params.set('redirect_uri', redirectUri);
    return `${baseUrl}/login/oauth/authorize?${params}`;
  }

  async function exchangeCode({ code, redirectUri }) {
    const body = new URLSearchParams({
      client_id: githubConfig.clientId,
      client_secret: githubConfig.clientSecret,
      code,
    });
    if (redirectUri) body.set('redirect_uri', redirectUri);
    const res = await fetchImpl(`${baseUrl}/login/oauth/access_token`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.access_token) {
      throw new Error(`GitHub token exchange failed: ${data.error_description || data.error || res.status}`);
    }
    return data.access_token;
  }

  async function api(pathname, token) {
    const res = await fetchImpl(`${apiUrl}${pathname}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: 'Bearer ' + token,
        'User-Agent': 'github-authenticator',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    if (!res.ok) throw new Error(`GitHub API ${pathname} failed with status ${res.status}`);
    return res.json();
  }

  async function getIdentity(token) {
    const user = await api('/user', token);
    let emails = [];
    try {
      emails = await api('/user/emails', token);
    } catch {
      // Without the user:email scope fall back to the public profile e-mail (unverified).
      emails = user.email ? [{ email: user.email, verified: false, primary: true }] : [];
    }
    return {
      id: user.id,
      login: user.login,
      name: user.name || user.login,
      avatarUrl: user.avatar_url,
      emails: Array.isArray(emails) ? emails : [],
    };
  }

  return { authorizeUrl, exchangeCode, getIdentity };
}
