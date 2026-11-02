// Run: GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... SESSION_SECRET=... node examples/node-http.js
// Zero-dependency example using node:http.
import http from 'node:http';
import { createAuthenticator, loadConfig } from 'github-authenticator';

const auth = createAuthenticator(await loadConfig());

http
  .createServer(async (req, res) => {
    if (await auth.handle(req, res)) return; // auth route or access denied

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    if (!req.user) return res.end('Anonymous – visit /auth/login');
    res.end(`Signed in as ${req.user.login}; roles: ${req.auth.roles.join(', ')}`);
  })
  .listen(3000, () => console.log('Listening on http://localhost:3000'));
