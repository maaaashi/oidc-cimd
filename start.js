// Runs the OP, the client, and both APIs in one container so that "localhost:<port>"
// means the same thing to the browser and to every process.
const { spawn } = require('node:child_process');

// RFC 8693: the APIs are also confidential clients of the OP (client_id = their resource identifier),
// so that they can exchange tokens. The OP only lets API A obtain tokens for API B, not the other way round.
const API_A_SECRET = 'api-a-demo-secret';
const API_B_SECRET = 'api-b-demo-secret';
const TOKEN_EXCHANGE_CLIENTS = {
  'http://localhost:5000': { client_secret: API_A_SECRET, allowed_targets: ['http://localhost:5001'] },
  'http://localhost:5001': { client_secret: API_B_SECRET, allowed_targets: [] },
};

const procs = [
  { dir: 'op', env: { TOKEN_EXCHANGE_CLIENTS: JSON.stringify(TOKEN_EXCHANGE_CLIENTS) } },
  { dir: 'client', env: {} },
  {
    dir: 'rs',
    env: { PORT: '5000', RESOURCE: 'http://localhost:5000', NAME: 'api-a', CLIENT_SECRET: API_A_SECRET, DOWNSTREAM: 'http://localhost:5001' },
  },
  {
    dir: 'rs',
    env: { PORT: '5001', RESOURCE: 'http://localhost:5001', NAME: 'api-b', CLIENT_SECRET: API_B_SECRET, DOWNSTREAM: 'http://localhost:5000' },
  },
];

const children = procs.map(({ dir, env }) =>
  spawn('node', ['server.js'], { cwd: `${__dirname}/${dir}`, env: { ...process.env, ...env }, stdio: 'inherit' }),
);

const stopAll = (code) => {
  for (const c of children) c.kill('SIGTERM');
  process.exit(code);
};
// If any process dies, stop everything so the failure is visible (and restartable) as a whole.
for (const c of children) c.on('exit', (code) => stopAll(code ?? 1));
process.on('SIGTERM', () => stopAll(0));
process.on('SIGINT', () => stopAll(0));
