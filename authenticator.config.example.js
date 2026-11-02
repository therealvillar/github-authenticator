// Copy this file to `authenticator.config.js` in your project and adjust it.
// Secrets are read from environment variables – never commit them.
import { defineConfig } from 'github-authenticator';

export default defineConfig({
  // --- GitHub OAuth App (https://github.com/settings/developers) -----------------------
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackUrl: process.env.GITHUB_CALLBACK_URL, // e.g. https://app.example.com/auth/callback
    scopes: ['read:user', 'user:email'],
    // For GitHub Enterprise Server:
    // baseUrl: 'https://github.example.com',
    // apiUrl: 'https://github.example.com/api/v3',
  },

  // --- Session cookie -----------------------------------------------------------------
  session: {
    secret: process.env.SESSION_SECRET, // >= 32 random characters
    cookieName: 'gh_auth',
    maxAge: 8 * 60 * 60, // seconds
    secure: process.env.NODE_ENV === 'production',
  },

  // --- Routes (all auth endpoints live under basePath) ---------------------------------
  routes: {
    basePath: '/auth',
    afterLogin: '/',
    afterLogout: '/',
  },

  // --- Required domain ----------------------------------------------------------------
  // Users must own a *verified* GitHub e-mail on one of these domains.
  domain: {
    allowed: ['example.com'],
    // usernameSuffix: '_example', // e.g. Enterprise Managed Users (octocat_example)
  },
  // Optional allow-list of GitHub logins (empty = anyone passing the domain check).
  allowedUsers: [],

  // --- Roles --------------------------------------------------------------------------
  // Roles bundle features and pages. '*' means everything.
  defaultRoles: ['member'], // given to every signed-in user
  roles: {
    admin: { features: ['*'], pages: ['*'] },
    editor: { features: ['edit-events', 'export'] },
    member: { features: ['view-calendar'] },
  },

  // --- Features (functions that can be switched on/off) -------------------------------
  //   enabled: false -> kill switch, off for everyone
  //   default: true  -> on for every signed-in user unless overridden
  //   public:  true  -> also on for anonymous visitors
  features: {
    'view-calendar': { default: true },
    'edit-events': {},
    export: {},
    'beta-dashboard': { enabled: true },
    'legacy-reports': { enabled: false },
  },

  // --- Per-user settings (keys are GitHub logins, case-insensitive) --------------------
  users: {
    octocat: { roles: ['admin'] },
    hubot: {
      roles: ['editor'],
      features: { export: false, 'beta-dashboard': true }, // per-user on/off toggles
      pages: { allow: ['/reports/**'], deny: ['/settings/**'] },
    },
  },

  // --- Page permissions (first matching rule wins) ------------------------------------
  //   '*' matches one path segment, '**' any number of segments.
  pages: [
    { path: '/', public: true },
    { path: '/public/**', public: true },
    { path: '/admin/**', roles: ['admin'] },
    { path: '/events/edit/**', features: ['edit-events'] },
    { path: '/reports/**', roles: ['admin', 'editor'] },
  ],
  defaultPageAccess: 'authenticated', // 'authenticated' | 'public' | 'deny'
  enforcePages: true,

  // --- User-requested password reset --------------------------------------------------
  passwordReset: {
    enabled: true,
    // 'github': redirect to GitHub's own password reset page (GitHub owns the password).
    // 'custom': token-based flow, you deliver the e-mail and store the new password.
    mode: 'github',
    // tokenTtl: 3600,
    // minPasswordLength: 12,
    // sendResetEmail: async ({ email, resetLink }) => mailer.send(email, resetLink),
    // onPasswordReset: async ({ email, password }) => users.setPassword(email, password),
  },
});
