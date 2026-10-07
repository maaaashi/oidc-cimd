// Runs the OP, the client, and both APIs in one container so that "localhost:<port>"
// means the same thing to the browser and to every process.
const { spawn } = require('node:child_process');

const procs = [
  { dir: 'op', env: {} },
  { dir: 'client', env: {} },
  { dir: 'rs', env: { PORT: '5000', RESOURCE: 'http://localhost:5000', NAME: 'api-a' } },
  { dir: 'rs', env: { PORT: '5001', RESOURCE: 'http://localhost:5001', NAME: 'api-b' } },
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
