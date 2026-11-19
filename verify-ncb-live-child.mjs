/*
The child process of verify-ncb-live.mjs: a FRESH relay boot — new process, new memory, no session
table to recover from — validating the handle the parent obtained from live NCB.

This is the only honest way to test restart-safety in this design. A same-process rebuild would prove
the seal opens, but not that a container restart does; a new process proves the claim the architecture
rests on, which is that no server-side state has to survive anything.

The handle arrives over the environment of a child this parent spawned, so it never touches disk.
*/
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(HERE, 'noop.cjs'));
const handle = String(process.env.LIVE_CHILD_BASE_HANDLE || '');
if (!handle) { console.log('CHILD_RESULT:{"error":"no handle supplied"}'); process.exit(2); }

const bridge = require(path.join(HERE, 'bridge.js'));
const relay = bridge.app.listen(0, '127.0.0.1');
await new Promise((r) => relay.once('listening', r));
const BASE = `http://127.0.0.1:${relay.address().port}`;
const ORIGIN = (String(process.env.NCB_GATEWAY_ALLOWED_ORIGINS || 'http://localhost:5173').split(',')[0] || '').trim();

const session = await fetch(`${BASE}/ncb/auth/get-session`, { headers: { Origin: ORIGIN, Authorization: `Bearer ${handle}` } });
const sessionJson = await session.json().catch(() => ({}));
const data = await fetch(`${BASE}/ncb/data/read/user_settings?limit=1`, { headers: { Origin: ORIGIN, Authorization: `Bearer ${handle}` } });
const dataJson = await data.json().catch(() => ({}));

// Nothing that could be a vendor cookie may appear in either answer.
const cookieExposed = JSON.stringify([sessionJson, dataJson]).includes('__Secure-better-auth');

console.log(`CHILD_RESULT:${JSON.stringify({
  session: session.status === 200 && sessionJson?.data?.user?.id !== undefined,
  data: data.status === 200 && Array.isArray(dataJson?.data),
  cookieExposed
})}`);

await new Promise((r) => relay.close(r));
process.exit(0);
