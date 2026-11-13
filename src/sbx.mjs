// Thin wrapper around the `sbx` CLI. Everything the TUI knows comes from here.

import { spawn } from 'node:child_process';
import { Worker } from 'node:worker_threads';

export const PROTOCOLS = ['tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6'];

export class SbxError extends Error {
  constructor(message, { code, args } = {}) {
    super(message);
    this.code = code;
    this.args = args;
  }
}

/** Turn sbx's stderr ("error: ...\n  try: ...") into a one-line message. */
export function cleanError(text) {
  const lines = String(text || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (!lines.length) return '';
  const main = lines.find((l) => /^error:/i.test(l)) || lines[0];
  return main.replace(/^error:\s*/i, '');
}

/**
 * Build a `--publish` spec: [[HOST_IP:]HOST_PORT:]SANDBOX_PORT[/PROTOCOL]
 * hostPort '' or 'auto' lets sbx pick an ephemeral host port.
 */
export function buildPortSpec({ sandboxPort, hostPort = '', hostIp = '', protocol = '' }) {
  const sp = parsePort(sandboxPort);
  if (sp === null) throw new Error('Sandbox port must be a number between 1 and 65535');
  let spec = String(sp);
  const hpRaw = String(hostPort ?? '').trim().toLowerCase();
  const auto = hpRaw === '' || hpRaw === 'auto' || hpRaw === '0';
  if (!auto) {
    const hp = parsePort(hpRaw);
    if (hp === null) throw new Error('Host port must be a number between 1 and 65535, or empty for automatic');
    spec = `${hp}:${spec}`;
    if (hostIp) spec = `${bracket(hostIp)}:${spec}`;
  } else if (hostIp) {
    throw new Error('A host port is required when binding to a specific address');
  }
  if (protocol) {
    if (!PROTOCOLS.includes(protocol)) throw new Error(`Unknown protocol: ${protocol}`);
    spec += `/${protocol}`;
  }
  return spec;
}

function bracket(ip) {
  return ip.includes(':') && !ip.startsWith('[') ? `[${ip}]` : ip;
}

export function parsePort(v) {
  const s = String(v ?? '').trim();
  if (!/^\d{1,5}$/.test(s)) return null;
  const n = Number(s);
  return n >= 1 && n <= 65535 ? n : null;
}

/** Spec that removes exactly the given published mapping. */
export function unpublishSpec(port) {
  let spec = `${port.host_port}:${port.sandbox_port}`;
  if (port.host_ip) spec = `${bracket(port.host_ip)}:${spec}`;
  if (port.protocol) spec += `/${port.protocol}`;
  return spec;
}

/** A URL a browser on the host can open for a published port, or null for UDP. */
export function portUrl(port) {
  if (String(port.protocol || 'tcp').startsWith('udp')) return null;
  let host = port.host_ip || 'localhost';
  if (host === '127.0.0.1' || host === '0.0.0.0' || host === '::1' || host === '::') host = 'localhost';
  else if (host.includes(':')) host = `[${host}]`;
  const scheme = port.sandbox_port === 443 || port.sandbox_port === 8443 ? 'https' : 'http';
  return `${scheme}://${host}:${port.host_port}`;
}

/** Parse `ss -tlnH` output and/or /proc/net/tcp{,6} content into listening TCP ports. */
export function parseListening(text) {
  const ports = new Set();
  for (const line of String(text || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    // ss: "LISTEN 0 511 0.0.0.0:8765 0.0.0.0:*" / "LISTEN 0 128 [::]:22 [::]:*" / "*:3000"
    let m = /^LISTEN\s+\d+\s+\d+\s+(\S+)\s/.exec(t);
    if (m) {
      const p = /:(\d+)$/.exec(m[1]);
      if (p) ports.add(Number(p[1]));
      continue;
    }
    // /proc/net/tcp: "0: 00000000:223D 00000000:0000 0A ..."
    m = /^\d+:\s+[0-9A-Fa-f]+:([0-9A-Fa-f]{4})\s+[0-9A-Fa-f]+:[0-9A-Fa-f]{4}\s+0A\s/.exec(t);
    if (m) ports.add(parseInt(m[1], 16));
  }
  return [...ports].filter((p) => p > 0).sort((a, b) => a - b);
}

/** Split "host:443" / "[::1]:443" / "host" into host and port. */
export function splitHostPort(resource) {
  const s = String(resource || '');
  let m = /^\[(.+)\]:(\d+)$/.exec(s);
  if (m) return { host: m[1], port: m[2] };
  m = /^([^:]+):(\d+)$/.exec(s);
  if (m) return { host: m[1], port: m[2] };
  return { host: s, port: '' };
}

/** Candidate rule patterns for a blocked/requested resource, most specific first. */
export function patternChoices(resource) {
  const { host, port } = splitHostPort(resource);
  const out = [{ pattern: resource, label: `${resource}`, hint: 'exactly this host and port' }];
  if (port && host) out.push({ pattern: host, label: host, hint: 'this host, any port' });
  const isIp = /^[\d.]+$/.test(host) || host.includes(':');
  const labels = host.split('.');
  if (!isIp && labels.length >= 3) {
    const parent = labels.slice(1).join('.');
    out.push({ pattern: `**.${parent}`, label: `**.${parent}`, hint: 'all subdomains, any port' });
  }
  return out;
}

export class Sbx {
  constructor({ bin = process.env.SBX_BIN || 'sbx', timeout = 30000 } = {}) {
    this.bin = bin;
    this.timeout = timeout;
  }

  /** Send a command to the least busy worker thread, starting workers on demand. */
  dispatch(args, timeout) {
    if (!this.workers) this.workers = [];
    let w = this.workers.find((x) => x.pending.size === 0);
    if (!w && this.workers.length < 3) {
      const worker = new Worker(new URL('./sbx-worker.mjs', import.meta.url));
      w = { worker, pending: new Map() };
      const failAll = (e) => {
        for (const { reject } of w.pending.values()) reject(new SbxError(e?.message || 'sbx worker stopped'));
        w.pending.clear();
        this.workers = this.workers.filter((x) => x !== w);
      };
      worker.on('message', (m) => {
        const p = w.pending.get(m.id);
        w.pending.delete(m.id);
        if (w.pending.size === 0) worker.unref(); // an idle worker must not keep the app alive
        p?.resolve(m);
      });
      worker.on('error', failAll);
      worker.on('exit', () => failAll());
      this.workers.push(w);
    }
    if (!w) w = this.workers.reduce((a, b) => (b.pending.size < a.pending.size ? b : a));
    const id = (this.seq = (this.seq || 0) + 1);
    return new Promise((resolve, reject) => {
      w.pending.set(id, { resolve, reject });
      w.worker.ref();
      w.worker.postMessage({ id, bin: this.bin, args, timeout });
    });
  }

  /** Run sbx and resolve with stdout; rejects with SbxError on failure. */
  async run(args, { timeout = this.timeout } = {}) {
    const { error, stdout, stderr } = await this.dispatch(['--no-input', ...args], timeout);
    if (!error) return stdout;
    let msg;
    if (error.code === 'ENOENT') msg = `Cannot find the '${this.bin}' command. Install Docker Sandboxes or set SBX_BIN.`;
    else if (error.killed) msg = `sbx ${args.join(' ')} timed out`;
    else msg = cleanError(stderr) || cleanError(stdout) || error.message;
    throw new SbxError(msg, { code: error.code, args });
  }

  async json(args, opts) {
    const out = await this.run([...args, '--json'], opts);
    const text = out.trim();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      throw new SbxError(`Unexpected output from sbx ${args.join(' ')}`, { args });
    }
  }

  async version() {
    const out = await this.run(['version']);
    const m = /v\d+\.\d+\.\d+\S*/.exec(out);
    return m ? m[0] : out.trim().split(/\r?\n/)[0];
  }

  async sandboxes() {
    return (await this.json(['ls'])) || [];
  }

  async approvals() {
    return (await this.json(['policy', 'approval', 'ls'])) || [];
  }

  respond(approvalId, optionId) {
    return this.run(['policy', 'approval', 'respond', approvalId, '--option', optionId]);
  }

  async policyLog() {
    const d = (await this.json(['policy', 'log'])) || {};
    return { allowed: d.allowed || [], blocked: d.blocked || [] };
  }

  /** decision: 'allow' | 'deny'. sandbox: name, or '' for all sandboxes. */
  addNetworkRule(decision, resource, sandbox = '') {
    const args = ['policy', decision, 'network'];
    if (sandbox) args.push('--sandbox', sandbox);
    args.push(resource);
    return this.run(args);
  }

  async ports(sandbox) {
    return (await this.json(['ports', sandbox])) || [];
  }

  publish(sandbox, spec) {
    // Publishing may have to boot a stopped sandbox, so allow plenty of time.
    return this.run(['ports', sandbox, '--publish', spec], { timeout: 180000 });
  }

  unpublish(sandbox, spec) {
    return this.run(['ports', sandbox, '--unpublish', spec]);
  }

  stop(name) {
    return this.run(['stop', name], { timeout: 120000 });
  }

  remove(name) {
    return this.run(['rm', '--force', name], { timeout: 120000 });
  }

  /** TCP ports something inside the (running) sandbox is listening on. Best effort. */
  async listening(sandbox) {
    try {
      const out = await this.run(
        ['exec', sandbox, 'sh', '-c', 'ss -tlnH 2>/dev/null; cat /proc/net/tcp /proc/net/tcp6 2>/dev/null'],
        { timeout: 10000 },
      );
      return parseListening(out);
    } catch {
      return [];
    }
  }

  /** Describe an interactive sbx command; the host runs it with the terminal attached. */
  interactive(args) {
    return { bin: this.bin, args };
  }
}

export function openInBrowser(url) {
  let cmd, args;
  if (process.platform === 'win32') {
    cmd = 'rundll32';
    args = ['url.dll,FileProtocolHandler', url];
  } else if (process.platform === 'darwin') {
    cmd = 'open';
    args = [url];
  } else {
    cmd = 'xdg-open';
    args = [url];
  }
  return detached(cmd, args);
}

export function copyToClipboard(text) {
  const [cmd, args] =
    process.platform === 'win32'
      ? ['clip', []]
      : process.platform === 'darwin'
        ? ['pbcopy', []]
        : process.env.WAYLAND_DISPLAY
          ? ['wl-copy', []]
          : ['xclip', ['-selection', 'clipboard']];
  return new Promise((resolve) => {
    try {
      const p = spawn(cmd, args, { stdio: ['pipe', 'ignore', 'ignore'], windowsHide: true });
      p.on('error', () => resolve(false));
      p.on('close', (code) => resolve(code === 0));
      p.stdin.end(text);
    } catch {
      resolve(false);
    }
  });
}

function detached(cmd, args) {
  return new Promise((resolve) => {
    try {
      const p = spawn(cmd, args, { stdio: 'ignore', detached: true, windowsHide: true });
      p.on('error', () => resolve(false));
      p.on('spawn', () => {
        p.unref();
        resolve(true);
      });
    } catch {
      resolve(false);
    }
  });
}
