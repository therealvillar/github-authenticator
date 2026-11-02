// Run: GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... SESSION_SECRET=... node examples/express-app.js
// (requires `npm install express` and an authenticator.config.js in the working directory)
import express from 'express';
import { createAuthenticator, loadConfig } from 'github-authenticator';

const auth = createAuthenticator(await loadConfig());
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(auth.middleware()); // auth routes + page permissions, sets req.user / req.auth

app.get('/', (req, res) => {
  res.send(req.user ? `Hello ${req.user.login} – <a href="/auth/logout">Sign out</a>` : '<a href="/auth/login">Sign in with GitHub</a>');
});

app.get('/dashboard', (req, res) => {
  res.json({ user: req.user, canExport: req.auth.hasFeature('export') });
});

app.get('/api/export', auth.requireFeature('export'), (req, res) => res.json({ ok: true }));
app.get('/admin', auth.requireRole('admin'), (req, res) => res.send('Admin area'));

app.listen(3000, () => console.log('Listening on http://localhost:3000'));
