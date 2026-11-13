import { test } from 'node:test';
import assert from 'node:assert/strict';
import { App, ago, findOption } from '../src/app.mjs';
import {
  buildPortSpec, unpublishSpec, portUrl, parseListening, patternChoices, cleanError, splitHostPort,
} from '../src/sbx.mjs';
import { fit, strWidth, Screen } from '../src/term.mjs';

// ── a fake sbx that records what the UI asks for ──────────────────────────
function fakeSbx(overrides = {}) {
  const calls = [];
  const state = {
    sandboxes: [
      { name: 'web', agent: 'claude', status: 'running', workspaces: ['C:\\work\\web'], last_used_at: new Date().toISOString(),
        ports: [{ host_ip: '127.0.0.1', host_port: 3000, sandbox_port: 3000, protocol: 'tcp4' }] },
      { name: 'api', agent: 'claude', status: 'stopped', workspaces: ['C:\\work\\api'], last_used_at: new Date().toISOString() },
    ],
    approvals: [
      { id: 'network:abc', sandbox_name: 'web', title: 'example.com:443', detail: 'Protocol: TCP\nResource type: domain',
        created_at: new Date().toISOString(), options: [{ id: 'allow', label: 'Allow' }, { id: 'dismiss', label: 'Dismiss' }] },
    ],
    log: {
      allowed: [],
      blocked: [
        { sandbox_id: 'web', host: 'example.com:443', count: 3, reason: 'default deny', last_seen: new Date().toISOString() },
        { sandbox_id: 'api', host: 'intake.logs.datadoghq.com:443', count: 16, reason: 'No matching allow rule', last_seen: new Date().toISOString() },
      ],
    },
  };
  const rec = (name, ret) => async (...a) => { calls.push([name, ...a]); return typeof ret === 'function' ? ret(...a) : ret; };
  return {
    calls,
    state,
    version: async () => 'v0.0.0',
    sandboxes: async () => structuredClone(state.sandboxes),
    approvals: async () => structuredClone(state.approvals),
    policyLog: async () => structuredClone(state.log),
    listening: async () => [8765, 3000],
    respond: rec('respond', (id) => { state.approvals = state.approvals.filter((a) => a.id !== id); return ''; }),
    addNetworkRule: rec('rule', ''),
    publish: rec('publish', (name, spec) => {
      const [hp, rest] = spec.split(':');
      const [sp, proto] = rest.split('/');
      state.sandboxes.find((s) => s.name === name).ports = [{ host_ip: '127.0.0.1', host_port: +hp, sandbox_port: +sp, protocol: proto }];
      return `Published 127.0.0.1:${hp} -> ${sp}/${proto}\n`;
    }),
    unpublish: rec('unpublish', ''),
    stop: rec('stop', ''),
    remove: rec('remove', ''),
    interactive: (args) => ({ bin: 'sbx', args }),
    ...overrides,
  };
}

async function boot(overrides, size = [110, 30]) {
  const sbx = fakeSbx(overrides);
  const out = [];
  const io = { write: (s) => out.push(s), columns: size[0], rows: size[1] };
  const app = new App({ sbx, io, bell: false });
  await app.refresh(true);
  return { app, sbx, text: () => { app.render(); return app.screen.toText(); } };
}
const keys = (app, ...ks) => ks.forEach((k) => app.key(k, k.length === 1 ? k : ''));
const settle = () => new Promise((r) => setTimeout(r, 20));

// ── pure helpers ──────────────────────────────────────────────────────────
test('buildPortSpec', () => {
  assert.equal(buildPortSpec({ sandboxPort: '8765', hostPort: '8765', protocol: 'tcp' }), '8765:8765/tcp');
  assert.equal(buildPortSpec({ sandboxPort: 8080, hostPort: '3000' }), '3000:8080');
  assert.equal(buildPortSpec({ sandboxPort: '8080', hostPort: '0', protocol: 'tcp4' }), '8080/tcp4');
  assert.equal(buildPortSpec({ sandboxPort: '80', hostPort: '8080', hostIp: '0.0.0.0', protocol: 'tcp4' }), '0.0.0.0:8080:80/tcp4');
  assert.equal(buildPortSpec({ sandboxPort: '80', hostPort: '8080', hostIp: '::1', protocol: 'tcp6' }), '[::1]:8080:80/tcp6');
  assert.throws(() => buildPortSpec({ sandboxPort: '' }));
  assert.throws(() => buildPortSpec({ sandboxPort: '70000' }));
  assert.throws(() => buildPortSpec({ sandboxPort: '80', hostPort: 'abc' }));
  assert.throws(() => buildPortSpec({ sandboxPort: '80', hostIp: '0.0.0.0' }));
});

test('unpublishSpec and portUrl', () => {
  const p = { host_ip: '127.0.0.1', host_port: 60000, sandbox_port: 59173, protocol: 'tcp4' };
  assert.equal(unpublishSpec(p), '127.0.0.1:60000:59173/tcp4');
  assert.equal(portUrl(p), 'http://localhost:60000');
  assert.equal(portUrl({ ...p, host_ip: '::1' }), 'http://localhost:60000');
  assert.equal(portUrl({ ...p, protocol: 'udp' }), null);
  assert.equal(portUrl({ ...p, sandbox_port: 443 }), 'https://localhost:60000');
});

test('parseListening understands ss and /proc/net/tcp', () => {
  const ss = 'LISTEN 0      511          0.0.0.0:8765       0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\nLISTEN 0 4096 *:3000 *:*';
  const proc = '  sl  local_address rem_address   st tx_queue\n   0: 00000000:223D 00000000:0000 0A 00000000:00000000\n   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000';
  assert.deepEqual(parseListening(ss), [22, 3000, 8765]);
  assert.deepEqual(parseListening(proc), [8765]);
  assert.deepEqual(parseListening(''), []);
});

test('patternChoices, splitHostPort, cleanError', () => {
  assert.deepEqual(patternChoices('a.b.example.com:443').map((c) => c.pattern), ['a.b.example.com:443', 'a.b.example.com', '**.b.example.com']);
  assert.deepEqual(patternChoices('example.com:443').map((c) => c.pattern), ['example.com:443', 'example.com']);
  assert.deepEqual(patternChoices('10.0.0.1:80').map((c) => c.pattern), ['10.0.0.1:80', '10.0.0.1']);
  assert.deepEqual(splitHostPort('[::1]:443'), { host: '::1', port: '443' });
  assert.equal(cleanError("error: sandbox 'x' not found\n  try: sbx ls\n"), "sandbox 'x' not found");
});

test('fit, strWidth, ago, findOption', () => {
  assert.equal(fit('abcdef', 4), 'abc…');
  assert.equal(fit('abcdef', 4, { from: 'start' }), '…def');
  assert.equal(fit('abc', 4), 'abc');
  assert.equal(strWidth('日本'), 4);
  assert.equal(ago(new Date(Date.now() - 125000).toISOString()), '2m');
  const a = { options: [{ id: 'allow' }, { id: 'dismiss' }] };
  assert.equal(findOption(a, 'allow').id, 'allow');
  assert.equal(findOption(a, 'deny').id, 'dismiss');
  assert.equal(findOption({ options: [{ id: 'dismiss' }, { id: 'deny' }] }, 'deny').id, 'deny');
});

test('screen flush only repaints changed rows', () => {
  const scr = new Screen(20, 3);
  const out = [];
  scr.put(0, 0, 'hello');
  scr.flush({ write: (s) => out.push(s) });
  scr.clear();
  scr.put(0, 0, 'hello');
  scr.put(0, 1, 'x');
  scr.flush({ write: (s) => out.push(s) });
  assert.ok(out[0].includes('hello'));
  assert.ok(!out[1].includes('hello'));
  assert.ok(out[1].includes('\x1b[2;1H'));
});

// ── the app, driven through its keys ──────────────────────────────────────
test('sandboxes view lists sandboxes with ports and pending badge', async () => {
  const { text } = await boot();
  const t = text();
  assert.match(t, /SANDBOX/);
  assert.match(t, /web .*●1 .*● running .*3000→3000/);
  assert.match(t, /api .*○ stopped/);
  assert.match(t, /1 request is waiting for approval/);
});

test('approvals: a allows, blocked duplicates of pending requests are hidden', async () => {
  const { app, sbx, text } = await boot();
  keys(app, '2');
  let t = text();
  assert.match(t, /PENDING APPROVALS \(1\)/);
  assert.match(t, /RECENTLY BLOCKED \(1\)/);
  assert.equal((t.match(/example\.com:443/g) || []).length, 1);
  assert.doesNotMatch(t, /undefined/);
  keys(app, 'a');
  await settle();
  assert.deepEqual(sbx.calls[0], ['respond', 'network:abc', 'allow']);
  assert.match(text(), /PENDING APPROVALS \(0\)/);
});

test('approvals: d picks the dismiss option', async () => {
  const { app, sbx } = await boot();
  keys(app, '2', 'd');
  await settle();
  assert.deepEqual(sbx.calls[0], ['respond', 'network:abc', 'dismiss']);
});

test('approvals: allow all asks first', async () => {
  const { app, sbx, text } = await boot();
  keys(app, '2', 'A');
  assert.match(text(), /Allow all 1 pending request\?/);
  keys(app, 'return'); // dangerous confirm needs an explicit y
  assert.equal(sbx.calls.length, 0);
  keys(app, 'y');
  await settle();
  assert.deepEqual(sbx.calls[0], ['respond', 'network:abc', 'allow']);
});

test('blocked host: a opens rule menu, choosing adds a sandbox-scoped allow rule', async () => {
  const { app, sbx, text } = await boot();
  keys(app, '2', 'down', 'a');
  const t = text();
  assert.match(t, /Add allow rule/);
  assert.match(t, /\*\*\.logs\.datadoghq\.com/);
  keys(app, 'return');
  await settle();
  assert.deepEqual(sbx.calls[0], ['rule', 'allow', 'intake.logs.datadoghq.com:443', 'api']);
  assert.match(text(), /RECENTLY BLOCKED \(0\)/);
});

test('blocked host: deny rule for all sandboxes', async () => {
  const { app, sbx } = await boot();
  keys(app, '2', 'down', 'd', 'down', 'return');
  await settle();
  assert.deepEqual(sbx.calls[0], ['rule', 'deny', 'intake.logs.datadoghq.com:443', '']);
});

test('port form: type a port, publish, lands on ports view', async () => {
  const { app, sbx, text } = await boot();
  keys(app, 'down', 'up', 'p'); // "api" is first alphabetically
  let t = text();
  assert.match(t, /Forward a port to this machine/);
  assert.match(t, /‹?\s*api/);
  assert.match(t, /this sandbox is stopped — publishing will start it/);
  keys(app, '8', '7', '6', '5');
  t = text();
  assert.match(t, /\$ sbx ports api --publish 8765:8765\/tcp4/);
  app.modal.open = false; // do not launch a real browser from the test
  keys(app, 'return');
  await settle();
  assert.deepEqual(sbx.calls[0], ['publish', 'api', '8765:8765/tcp4']);
  assert.equal(app.modal, null);
  assert.equal(app.view, 'ports');
  t = text();
  assert.match(t, /api\s+127\.0\.0\.1:8765\s+→\s+8765\s+tcp4\s+http:\/\/localhost:8765/);
  assert.equal(app.current().sandbox, 'api');
});

test('port form: custom host port, protocol, listening-port picker, errors stay in the form', async () => {
  const { app, sbx, text } = await boot({
    publish: async () => { throw new Error('port 9000 is already in use'); },
  });
  keys(app, 'down', 'p'); // web (running)
  await settle();
  assert.match(text(), /listening: 8765/); // 3000 is already published, so not offered
  keys(app, 'right'); // pick detected port
  assert.equal(app.modal.sandboxPort, '8765');
  keys(app, 'tab', '9', '0', '0', '0', 'tab', 'right');
  assert.match(text(), /\$ sbx ports web --publish 9000:8765\/tcp /);
  app.modal.open = false;
  keys(app, 'return');
  await settle();
  assert.ok(app.modal, 'form stays open on failure');
  assert.match(text(), /✗ port 9000 is already in use/);
  assert.equal(sbx.calls.length, 0);
});

test('port form: validation and escape', async () => {
  const { app, sbx, text } = await boot();
  keys(app, 'p', 'return');
  assert.match(text(), /Sandbox port must be a number/);
  keys(app, 'escape');
  assert.equal(app.modal, null);
  assert.equal(sbx.calls.length, 0);
});

test('ports view: unpublish uses the exact mapping', async () => {
  const { app, sbx, text } = await boot();
  keys(app, '3');
  assert.match(text(), /web\s+127\.0\.0\.1:3000/);
  keys(app, 'd');
  assert.match(text(), /Stop forwarding 127\.0\.0\.1:3000 → web:3000\/tcp4\?/);
  keys(app, 'return');
  await settle();
  assert.deepEqual(sbx.calls[0], ['unpublish', 'web', '127.0.0.1:3000:3000/tcp4']);
});

test('remove needs y, stop refuses on a stopped sandbox', async () => {
  const { app, sbx, text } = await boot();
  keys(app, 'x', 'return');
  assert.equal(sbx.calls.length, 0);
  keys(app, 'n');
  keys(app, 's');
  assert.match(text(), /api is not running/);
  keys(app, 'x', 'y');
  await settle();
  assert.deepEqual(sbx.calls[0], ['remove', 'api']);
});

test('renders at small and odd sizes without throwing', async () => {
  for (const size of [[50, 10], [60, 14], [200, 60], [20, 5]]) {
    const { app, text } = await boot({}, size);
    for (const k of ['1', '2', '3', '?', 'escape', 'p', 'escape']) { keys(app, k); text(); }
  }
});
