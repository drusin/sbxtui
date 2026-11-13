// sbxtui application: state, rendering and key handling.

import { Screen, S, withSel, fit, strWidth } from './term.mjs';
import {
  PROTOCOLS,
  buildPortSpec,
  unpublishSpec,
  portUrl,
  parsePort,
  patternChoices,
  openInBrowser,
  copyToClipboard,
} from './sbx.mjs';

const VIEWS = ['sandboxes', 'approvals', 'ports'];
const VIEW_TITLES = { sandboxes: 'Sandboxes', approvals: 'Approvals', ports: 'Ports' };
const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

const PROTO_ORDER = ['tcp4', 'tcp', 'tcp6', 'udp4', 'udp', 'udp6'].filter((p) => PROTOCOLS.includes(p));
const PROTO_HINT = {
  tcp4: 'TCP, IPv4 (sbx default, best for browsers)',
  tcp: 'TCP, IPv4 + IPv6',
  tcp6: 'TCP, IPv6 only',
  udp4: 'UDP, IPv4',
  udp: 'UDP, IPv4 + IPv6',
  udp6: 'UDP, IPv6 only',
};
const BINDS = [
  { id: 'local', label: 'this machine only', ip: '' },
  { id: 'all', label: 'whole network (0.0.0.0)', ip: '0.0.0.0' },
];

export function ago(iso, now = Date.now()) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export function findOption(approval, kind) {
  const opts = approval.options || [];
  if (kind === 'allow') return opts.find((o) => /allow|approve|accept|yes/i.test(o.id));
  return opts.find((o) => /deny|reject|block/i.test(o.id)) || opts.find((o) => /dismiss|cancel|no/i.test(o.id));
}

const portKey = (name, p) => `${name}|${p.host_ip}|${p.host_port}|${p.sandbox_port}|${p.protocol}`;

export class App {
  /**
   * io: { write(str), columns, rows }
   * hooks: { suspend(fn) -> Promise, quit() }
   */
  constructor({ sbx, io, hooks = {}, interval = 2000, bell = true }) {
    this.sbx = sbx;
    this.io = io;
    this.hooks = hooks;
    this.interval = interval;
    this.bell = bell;
    this.screen = new Screen(io.columns || 80, io.rows || 24);

    this.view = 'sandboxes';
    this.sandboxes = [];
    this.approvals = [];
    this.blocked = [];
    this.allowedLog = [];
    this.handled = new Set(); // blocked entries the user already added a rule for
    this.loaded = false;
    this.loadError = '';
    this.version = '';
    this.sel = { sandboxes: 0, approvals: 0, ports: 0 };
    this.selKey = { sandboxes: null, approvals: null, ports: null };
    this.scroll = { sandboxes: 0, approvals: 0, ports: 0 };
    this.modal = null;
    this.toast = null;
    this.busy = '';
    this.spin = 0;
    this.suspended = false;
    this.seenApprovals = null;
    this.listenCache = new Map();
    this.tick = 0;
    this.refreshing = false;
    this.timers = [];
  }

  // ───────────────────────────── lifecycle ─────────────────────────────

  start() {
    this.render();
    this.sbx.version().then((v) => { this.version = v; this.render(); }, () => {});
    this.refresh(true);
    this.timers.push(setInterval(() => this.refresh(false), this.interval));
    this.timers.push(setInterval(() => {
      if (this.busy || !this.loaded) { this.spin++; this.render(); }
      if (this.toast && Date.now() > this.toast.until) { this.toast = null; this.render(); }
    }, 120));
  }

  stop() {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
  }

  resize(cols, rows) {
    this.screen.resize(cols, rows);
    this.render();
  }

  async refresh(full) {
    if (this.refreshing || this.suspended) return;
    this.refreshing = true;
    const wantLog = full || this.tick % 3 === 0;
    this.tick++;
    try {
      const [sb, ap, log] = await Promise.allSettled([
        this.sbx.sandboxes(),
        this.sbx.approvals(),
        wantLog ? this.sbx.policyLog() : Promise.resolve(null),
      ]);
      if (sb.status === 'fulfilled') {
        this.sandboxes = sb.value.slice().sort((a, b) => a.name.localeCompare(b.name));
        this.loadError = '';
      } else {
        this.loadError = sb.reason.message;
      }
      if (ap.status === 'fulfilled') {
        this.approvals = ap.value.slice().sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
        const ids = new Set(this.approvals.map((a) => a.id));
        if (this.seenApprovals && this.bell && [...ids].some((id) => !this.seenApprovals.has(id))) {
          this.io.write('\x07');
        }
        this.seenApprovals = ids;
      }
      if (log.status === 'fulfilled' && log.value) {
        this.blocked = log.value.blocked;
        this.allowedLog = log.value.allowed;
      }
      this.loaded = true;
    } finally {
      this.refreshing = false;
    }
    if (this.modal?.type === 'form') this.ensureListening(this.modal.sandbox);
    this.render();
  }

  // ───────────────────────────── derived data ─────────────────────────────

  /** Blocked log entries that are still worth acting on. */
  blockedRows() {
    const pending = new Set(this.approvals.map((a) => `${a.sandbox_name}|${a.title}`));
    const allowedAt = new Map();
    for (const a of this.allowedLog) {
      const k = `${a.sandbox_id}|${a.host}`;
      const t = Date.parse(a.last_seen) || 0;
      if (t > (allowedAt.get(k) || 0)) allowedAt.set(k, t);
    }
    const merged = new Map();
    for (const b of this.blocked) {
      const k = `${b.sandbox_id}|${b.host}`;
      if (pending.has(k) || this.handled.has(k)) continue;
      if ((allowedAt.get(k) || 0) > (Date.parse(b.last_seen) || 0)) continue;
      const cur = merged.get(k);
      if (cur) {
        cur.count += b.count || 0;
        if (String(b.last_seen) > String(cur.last_seen)) cur.last_seen = b.last_seen;
      } else {
        merged.set(k, { ...b, kind: 'blocked', key: `b:${k}` });
      }
    }
    return [...merged.values()].sort((a, b) => String(b.last_seen).localeCompare(String(a.last_seen)));
  }

  approvalRows() {
    return [
      ...this.approvals.map((a) => ({ ...a, kind: 'approval', key: `a:${a.id}` })),
      ...this.blockedRows(),
    ];
  }

  portRows() {
    const rows = [];
    for (const s of this.sandboxes) {
      for (const p of s.ports || []) rows.push({ ...p, sandbox: s.name, key: portKey(s.name, p) });
    }
    return rows;
  }

  rowsFor(view = this.view) {
    if (view === 'sandboxes') return this.sandboxes.map((s) => ({ ...s, key: s.name }));
    if (view === 'approvals') return this.approvalRows();
    return this.portRows();
  }

  /** Keep the selection on the same item across refreshes. */
  syncSelection(view, rows) {
    const key = this.selKey[view];
    if (key != null) {
      const i = rows.findIndex((r) => r.key === key);
      if (i >= 0) this.sel[view] = i;
    }
    this.sel[view] = Math.max(0, Math.min(this.sel[view], rows.length - 1));
    this.selKey[view] = rows[this.sel[view]]?.key ?? null;
  }

  current() {
    const rows = this.rowsFor();
    this.syncSelection(this.view, rows);
    return rows[this.sel[this.view]] || null;
  }

  move(delta) {
    const rows = this.rowsFor();
    if (!rows.length) return;
    this.syncSelection(this.view, rows);
    const i = Math.max(0, Math.min(rows.length - 1, this.sel[this.view] + delta));
    this.sel[this.view] = i;
    this.selKey[this.view] = rows[i].key;
  }

  pendingCount(name) {
    return this.approvals.filter((a) => a.sandbox_name === name).length;
  }

  // ───────────────────────────── feedback ─────────────────────────────

  notify(text, kind = 'ok') {
    this.toast = { text: String(text).trim().split(/\r?\n/)[0], kind, until: Date.now() + (kind === 'error' ? 9000 : 5000) };
    this.render();
  }

  async withBusy(label, fn) {
    if (this.busy) return undefined;
    this.busy = label;
    this.render();
    try {
      return await fn();
    } catch (e) {
      this.notify(e.message || String(e), 'error');
      return undefined;
    } finally {
      this.busy = '';
      this.render();
    }
  }

  // ───────────────────────────── actions ─────────────────────────────

  async respond(approval, option) {
    await this.withBusy(`${option.label || option.id}: ${approval.title}`, async () => {
      await this.sbx.respond(approval.id, option.id);
      this.approvals = this.approvals.filter((a) => a.id !== approval.id);
      this.notify(`${option.label || option.id}: ${approval.title} (${approval.sandbox_name})`);
    });
    this.refresh(true);
  }

  async respondAll(kind) {
    const todo = this.approvals.map((a) => [a, findOption(a, kind)]).filter(([, o]) => o);
    await this.withBusy(`Responding to ${todo.length} approvals`, async () => {
      let ok = 0;
      const errors = [];
      for (const [a, o] of todo) {
        try { await this.sbx.respond(a.id, o.id); ok++; } catch (e) { errors.push(e.message); }
      }
      if (errors.length) this.notify(`${ok} done, ${errors.length} failed: ${errors[0]}`, 'error');
      else this.notify(`${kind === 'allow' ? 'Allowed' : 'Dismissed'} ${ok} request${ok === 1 ? '' : 's'}`);
    });
    this.refresh(true);
  }

  async addRule(decision, row, pattern, sandbox) {
    await this.withBusy(`Adding ${decision} rule for ${pattern}`, async () => {
      await this.sbx.addNetworkRule(decision, pattern, sandbox);
      this.handled.add(`${row.sandbox_id}|${row.host}`);
      this.notify(`${decision === 'allow' ? 'Allowed' : 'Denied'} ${pattern} for ${sandbox || 'all sandboxes'}`);
    });
    this.refresh(true);
  }

  async attach(args, label) {
    if (!this.hooks.suspend) return;
    this.suspended = true;
    let code = 0;
    try {
      code = await this.hooks.suspend(() => this.sbx.interactive(args));
    } catch (e) {
      this.notify(e.message, 'error');
    }
    this.suspended = false;
    this.screen.resize(this.io.columns || 80, this.io.rows || 24);
    if (code) this.notify(`${label} exited with code ${code}`, 'error');
    this.render();
    this.refresh(true);
  }

  async publish(form) {
    let spec;
    try {
      spec = this.formSpec(form);
    } catch (e) {
      form.error = e.message;
      this.render();
      return;
    }
    form.error = '';
    form.submitting = true;
    this.busy = `Publishing ${spec} on ${form.sandbox}`;
    this.render();
    try {
      const out = await this.sbx.publish(form.sandbox, spec);
      this.modal = null;
      const m = /Published\s+(\S+):(\d+)\s*->\s*(\d+)\/(\S+)/.exec(out);
      const port = m
        ? { host_ip: m[1].replace(/^\[|\]$/g, ''), host_port: Number(m[2]), sandbox_port: Number(m[3]), protocol: m[4] }
        : null;
      const url = port && portUrl(port);
      this.notify(url ? `Published ${url} → ${form.sandbox}:${port.sandbox_port}` : out || `Published ${spec}`);
      this.view = 'ports';
      if (port) {
        // sbx may report several bindings (IPv4 + IPv6); select by sandbox + ports.
        this.pendingPortSelect = { sandbox: form.sandbox, host_port: port.host_port, sandbox_port: port.sandbox_port };
      }
      if (form.open && url) openInBrowser(url);
    } catch (e) {
      form.error = e.message;
    } finally {
      form.submitting = false;
      this.busy = '';
    }
    await this.refresh(true);
    if (this.pendingPortSelect) {
      const want = this.pendingPortSelect;
      this.pendingPortSelect = null;
      const row = this.portRows().find(
        (r) => r.sandbox === want.sandbox && r.host_port === want.host_port && r.sandbox_port === want.sandbox_port,
      );
      if (row) this.selKey.ports = row.key;
    }
    this.render();
  }

  async unpublish(row) {
    await this.withBusy(`Removing ${row.host_port} → ${row.sandbox}:${row.sandbox_port}`, async () => {
      await this.sbx.unpublish(row.sandbox, unpublishSpec(row));
      const s = this.sandboxes.find((x) => x.name === row.sandbox);
      if (s?.ports) s.ports = s.ports.filter((p) => portKey(s.name, p) !== row.key);
      this.notify(`Unpublished ${row.host_port} → ${row.sandbox}:${row.sandbox_port}`);
    });
    // sbx applies unpublish asynchronously; give it a moment before re-reading.
    setTimeout(() => this.refresh(true), 800);
  }

  // ───────────────────────────── port form ─────────────────────────────

  openPortForm(sandboxName) {
    const names = this.sandboxes
      .slice()
      .sort((a, b) => (a.status === 'running' ? 0 : 1) - (b.status === 'running' ? 0 : 1) || a.name.localeCompare(b.name))
      .map((s) => s.name);
    if (!names.length) {
      this.notify('There are no sandboxes to forward a port from', 'error');
      return;
    }
    const sandbox = names.includes(sandboxName) ? sandboxName : names[0];
    this.modal = {
      type: 'form',
      names,
      sandbox,
      sandboxPort: '',
      hostPort: '',
      protocol: PROTO_ORDER[0],
      bind: 0,
      open: true,
      field: 1,
      error: '',
      submitting: false,
    };
    this.ensureListening(sandbox);
    this.render();
  }

  ensureListening(name) {
    const s = this.sandboxes.find((x) => x.name === name);
    if (!s || s.status !== 'running') return;
    const c = this.listenCache.get(name);
    if (c && (c.pending || Date.now() - c.at < 5000)) return;
    this.listenCache.set(name, { ports: c?.ports || [], at: Date.now(), pending: true });
    this.sbx.listening(name).then((ports) => {
      this.listenCache.set(name, { ports, at: Date.now(), pending: false });
      this.render();
    });
  }

  /** Listening ports in the form's sandbox that are not published yet. */
  listeningFor(name) {
    const s = this.sandboxes.find((x) => x.name === name);
    const published = new Set((s?.ports || []).map((p) => p.sandbox_port));
    return (this.listenCache.get(name)?.ports || []).filter((p) => !published.has(p));
  }

  formSpec(form) {
    const hostPort = form.hostPort === '' ? form.sandboxPort : form.hostPort;
    return buildPortSpec({
      sandboxPort: form.sandboxPort,
      hostPort,
      hostIp: BINDS[form.bind].ip,
      protocol: form.protocol,
    });
  }

  formKey(k, str) {
    const f = this.modal;
    if (f.submitting) return;
    const FIELDS = 6;
    const cycle = (arr, cur, d) => arr[(arr.indexOf(cur) + d + arr.length) % arr.length];
    if (k === 'escape') { this.modal = null; return; }
    if (k === 'return') { this.publish(f); return; }
    if (k === 'tab' || k === 'down') { f.field = (f.field + 1) % FIELDS; return; }
    if (k === 'shift+tab' || k === 'up') { f.field = (f.field + FIELDS - 1) % FIELDS; return; }
    f.error = '';
    const d = k === 'left' ? -1 : k === 'right' ? 1 : 0;
    switch (f.field) {
      case 0:
        if (d) { f.sandbox = cycle(f.names, f.sandbox, d); this.ensureListening(f.sandbox); }
        break;
      case 1:
      case 2: {
        const prop = f.field === 1 ? 'sandboxPort' : 'hostPort';
        if (k === 'backspace') f[prop] = f[prop].slice(0, -1);
        else if (k === 'ctrl+u' || k === 'delete') f[prop] = '';
        else if (str && /^\d+$/.test(str)) f[prop] = (f[prop] + str).slice(0, 5);
        else if (d && f.field === 1) {
          const ports = this.listeningFor(f.sandbox).map(String);
          if (ports.length) {
            const i = ports.indexOf(f.sandboxPort);
            f.sandboxPort = i < 0 ? ports[d > 0 ? 0 : ports.length - 1] : ports[(i + d + ports.length) % ports.length];
          }
        }
        break;
      }
      case 3:
        if (d || k === 'space') f.protocol = cycle(PROTO_ORDER, f.protocol, d || 1);
        break;
      case 4:
        if (d || k === 'space') f.bind = (f.bind + 1) % BINDS.length;
        break;
      case 5:
        if (d || k === 'space') f.open = !f.open;
        break;
    }
  }

  // ───────────────────────────── modals ─────────────────────────────

  confirm({ title, lines, danger = false, yes }) {
    this.modal = { type: 'confirm', title, lines, danger, yes };
  }

  menu({ title, subtitle = '', items }) {
    this.modal = { type: 'menu', title, subtitle, items, sel: 0 };
  }

  ruleMenu(decision, row) {
    const items = [];
    for (const c of patternChoices(row.host)) {
      items.push({
        label: c.pattern,
        hint: `${c.hint} · only ${row.sandbox_id}`,
        run: () => this.addRule(decision, row, c.pattern, row.sandbox_id),
      });
      items.push({
        label: c.pattern,
        hint: `${c.hint} · all sandboxes`,
        run: () => this.addRule(decision, row, c.pattern, ''),
      });
    }
    this.menu({
      title: decision === 'allow' ? 'Add allow rule' : 'Add deny rule',
      subtitle: `${row.sandbox_id} was blocked from ${row.host}`,
      items,
    });
  }

  modalKey(k, str) {
    const m = this.modal;
    if (m.type === 'form') return this.formKey(k, str);
    if (m.type === 'help') { this.modal = null; return undefined; }
    if (m.type === 'confirm') {
      if (k === 'y' || k === 'Y' || (k === 'return' && !m.danger)) { this.modal = null; m.yes(); }
      else if (k === 'n' || k === 'N' || k === 'escape' || k === 'q') this.modal = null;
      return undefined;
    }
    if (m.type === 'menu') {
      if (k === 'escape' || k === 'q') this.modal = null;
      else if (k === 'up' || k === 'k') m.sel = (m.sel + m.items.length - 1) % m.items.length;
      else if (k === 'down' || k === 'j') m.sel = (m.sel + 1) % m.items.length;
      else if (k === 'return') { this.modal = null; m.items[m.sel].run(); }
      else if (/^[1-9]$/.test(k) && m.items[Number(k) - 1]) { this.modal = null; m.items[Number(k) - 1].run(); }
    }
    return undefined;
  }

  // ───────────────────────────── keys ─────────────────────────────

  /** k: normalized key name; str: the typed character(s), if any. */
  key(k, str = '') {
    if (this.suspended) return;
    if (k === 'ctrl+c') { this.hooks.quit?.(); return; }
    if (this.modal) {
      this.modalKey(k, str);
      this.render();
      return;
    }
    const page = Math.max(1, this.screen.rows - 8);
    switch (k) {
      case 'q': this.hooks.quit?.(); return;
      case '?': this.modal = { type: 'help' }; break;
      case '1': case '2': case '3': this.view = VIEWS[Number(k) - 1]; break;
      case 'tab': case 'right': case 'l': this.view = VIEWS[(VIEWS.indexOf(this.view) + 1) % VIEWS.length]; break;
      case 'shift+tab': case 'left': case 'h': this.view = VIEWS[(VIEWS.indexOf(this.view) + VIEWS.length - 1) % VIEWS.length]; break;
      case 'up': case 'k': this.move(-1); break;
      case 'down': case 'j': this.move(1); break;
      case 'pageup': this.move(-page); break;
      case 'pagedown': this.move(page); break;
      case 'home': case 'g': this.move(-1e9); break;
      case 'end': case 'G': this.move(1e9); break;
      case 'r': this.refresh(true); this.notify('Refreshed'); break;
      default: this.viewKey(k);
    }
    this.render();
  }

  viewKey(k) {
    const row = this.current();
    if (this.view === 'sandboxes') {
      if (k === 'p' || k === 'n') return this.openPortForm(row?.name);
      if (!row) return undefined;
      if (k === 'return') return this.attach(['run', '--name', row.name], `sbx run --name ${row.name}`);
      if (k === 'e') return this.attach(['exec', '-it', row.name, 'bash'], `shell in ${row.name}`);
      if (k === 'a') { this.view = 'approvals'; return undefined; }
      if (k === 's') {
        if (row.status !== 'running') return this.notify(`${row.name} is not running`, 'error');
        return this.confirm({
          title: 'Stop sandbox',
          lines: [`Stop ${row.name}?`, 'Published ports are released when it stops.'],
          yes: () => this.withBusy(`Stopping ${row.name}`, async () => {
            await this.sbx.stop(row.name);
            this.notify(`Stopped ${row.name}`);
          }).then(() => this.refresh(true)),
        });
      }
      if (k === 'x' || k === 'delete') {
        return this.confirm({
          title: 'Remove sandbox',
          danger: true,
          lines: [`Permanently remove ${row.name}?`, 'Its container and state are deleted. This cannot be undone.', 'Workspace files on your machine are kept.'],
          yes: () => this.withBusy(`Removing ${row.name}`, async () => {
            await this.sbx.remove(row.name);
            this.notify(`Removed ${row.name}`);
          }).then(() => this.refresh(true)),
        });
      }
      return undefined;
    }

    if (this.view === 'approvals') {
      if (k === 'A' && this.approvals.length) {
        return this.confirm({
          title: 'Allow all',
          lines: [`Allow all ${this.approvals.length} pending request${this.approvals.length === 1 ? '' : 's'}?`],
          danger: true,
          yes: () => this.respondAll('allow'),
        });
      }
      if (k === 'D' && this.approvals.length) {
        return this.confirm({
          title: 'Dismiss all',
          lines: [`Deny/dismiss all ${this.approvals.length} pending request${this.approvals.length === 1 ? '' : 's'}?`],
          yes: () => this.respondAll('deny'),
        });
      }
      if (!row) return undefined;
      if (row.kind === 'approval') {
        if (k === 'a' || k === 'd') {
          const opt = findOption(row, k === 'a' ? 'allow' : 'deny');
          if (!opt) return this.notify(`This request has no ${k === 'a' ? 'allow' : 'deny'} option — press enter to see its options`, 'error');
          return this.respond(row, opt);
        }
        if (k === 'return') {
          return this.menu({
            title: row.title,
            subtitle: `${row.sandbox_name} · ${String(row.detail || '').replace(/\s*\n\s*/g, ' · ')}`,
            items: (row.options || []).map((o) => ({ label: o.label || o.id, hint: '', run: () => this.respond(row, o) })),
          });
        }
      } else {
        if (k === 'a' || k === 'return') return this.ruleMenu('allow', row);
        if (k === 'd') return this.ruleMenu('deny', row);
        if (k === 'x') { this.handled.add(`${row.sandbox_id}|${row.host}`); return undefined; }
      }
      return undefined;
    }

    // ports
    if (k === 'n' || k === 'p' || k === 'a') return this.openPortForm(row?.sandbox || this.selKey.sandboxes);
    if (!row) return undefined;
    const url = portUrl(row);
    if (k === 'o' || k === 'return') {
      if (!url) return this.notify('UDP ports cannot be opened in a browser', 'error');
      openInBrowser(url).then((ok) => this.notify(ok ? `Opened ${url}` : `Could not open a browser for ${url}`, ok ? 'ok' : 'error'));
      return undefined;
    }
    if (k === 'c') {
      const text = url || `${row.host_ip}:${row.host_port}`;
      copyToClipboard(text).then((ok) => this.notify(ok ? `Copied ${text}` : 'Could not reach the clipboard', ok ? 'ok' : 'error'));
      return undefined;
    }
    if (k === 'd' || k === 'x' || k === 'delete') {
      return this.confirm({
        title: 'Unpublish port',
        lines: [`Stop forwarding ${row.host_ip}:${row.host_port} → ${row.sandbox}:${row.sandbox_port}/${row.protocol}?`],
        yes: () => this.unpublish(row),
      });
    }
    return undefined;
  }

  // ───────────────────────────── rendering ─────────────────────────────

  render() {
    if (this.suspended) return;
    const scr = this.screen;
    scr.clear();
    const { cols, rows } = scr;
    if (cols < 50 || rows < 10) {
      scr.put(1, 0, 'sbxtui needs a terminal of at least 50×10', S.yellow);
      scr.flush(this.io);
      return;
    }

    this.drawHeader();
    scr.hline(0, 1, cols);
    const bodyY = 2;
    const bodyH = rows - 4;
    if (!this.loaded) {
      scr.put(2, bodyY + 1, `${SPINNER[this.spin % SPINNER.length]} Loading sandboxes…`, S.dim);
    } else if (this.view === 'sandboxes') this.drawSandboxes(bodyY, bodyH);
    else if (this.view === 'approvals') this.drawApprovals(bodyY, bodyH);
    else this.drawPorts(bodyY, bodyH);

    this.drawStatus(rows - 2);
    this.drawFooter(rows - 1);
    if (this.modal) this.drawModal();
    scr.flush(this.io);
  }

  drawHeader() {
    const scr = this.screen;
    let x = scr.put(1, 0, '◆ sbxtui', S.accentBold) + 3;
    VIEWS.forEach((v, i) => {
      const active = v === this.view;
      x = scr.put(x, 0, ` ${i + 1} ${VIEW_TITLES[v]} `, active ? S.tabActive : S.tab);
      if (v === 'approvals' && this.approvals.length) x = scr.put(x + 1, 0, ` ${this.approvals.length} `, S.badge);
      if (v === 'ports') {
        const n = this.portRows().length;
        if (n) x = scr.put(x + 1, 0, `${n}`, S.dim);
      }
      x += 2;
    });
    const right = this.version ? `sbx ${this.version}` : '';
    if (right && x + right.length + 2 < scr.cols) scr.put(scr.cols - right.length - 1, 0, right, S.faint);
  }

  drawStatus(y) {
    const scr = this.screen;
    if (this.busy) {
      scr.put(1, y, `${SPINNER[this.spin % SPINNER.length]} ${this.busy}…`, S.accent);
    } else if (this.toast) {
      const err = this.toast.kind === 'error';
      scr.put(1, y, `${err ? '✗' : '✓'} ${fit(this.toast.text, scr.cols - 4)}`, err ? S.red : S.green);
    } else if (this.loadError) {
      scr.put(1, y, `✗ ${fit(this.loadError, scr.cols - 4)}`, S.red);
    } else if (this.approvals.length && this.view !== 'approvals') {
      const n = this.approvals.length;
      scr.put(1, y, `● ${n} request${n === 1 ? ' is' : 's are'} waiting for approval — press 2`, S.yellow);
    }
  }

  footerHints() {
    if (this.modal) return [];
    const row = this.current();
    const common = [['tab', 'switch view'], ['?', 'help'], ['q', 'quit']];
    if (this.view === 'sandboxes') {
      return [['enter', 'attach'], ['e', 'shell'], ['p', 'forward port'], ['s', 'stop'], ['x', 'remove'], ...common];
    }
    if (this.view === 'approvals') {
      const h = [];
      if (row?.kind === 'approval') {
        const al = findOption(row, 'allow');
        const dn = findOption(row, 'deny');
        if (al) h.push(['a', al.label || 'allow']);
        if (dn) h.push(['d', dn.label || 'deny']);
        h.push(['enter', 'options']);
      } else if (row?.kind === 'blocked') {
        h.push(['a', 'allow rule…'], ['d', 'deny rule…'], ['x', 'hide']);
      }
      if (this.approvals.length > 1) h.push(['A', 'allow all'], ['D', 'dismiss all']);
      return [...h, ...common];
    }
    const h = [['n', 'new forward']];
    if (row) h.push(['o', 'open in browser'], ['c', 'copy URL'], ['d', 'unpublish']);
    return [...h, ...common];
  }

  drawFooter(y) {
    const scr = this.screen;
    let x = 1;
    for (const [key, label] of this.footerHints()) {
      if (x + key.length + label.length + 3 > scr.cols) break;
      x = scr.put(x, y, key, S.key);
      x = scr.put(x + 1, y, label, S.dim) + 3;
    }
  }

  /**
   * Draw a table. columns: [{ title, min, max, flex, cell(row) -> string | [string, style] }]
   * rows may contain { section: 'TITLE', note } separators, which are not selectable.
   */
  drawTable(view, y, h, columns, rows, lines = rows) {
    const scr = this.screen;
    const W = scr.cols - 3;
    const items = lines.filter((r) => r.section === undefined);
    const cells = new Map(items.map((r) => [r, columns.map((c) => {
      const v = c.cell(r);
      return Array.isArray(v) ? v : [v, ''];
    })]));
    const gap = 2;
    const widths = columns.map((c, i) => {
      let w = strWidth(c.title);
      for (const r of items) w = Math.max(w, strWidth(cells.get(r)[i][0]));
      return Math.max(c.min || 0, Math.min(c.max || 999, w));
    });
    const total = () => widths.reduce((a, b) => a + b, 0) + gap * (columns.length - 1);
    // shrink flexible columns (widest first) until the table fits
    for (let guard = 0; total() > W && guard < 500; guard++) {
      let best = -1;
      columns.forEach((c, i) => {
        if (c.flex && widths[i] > (c.min || 4) && (best < 0 || widths[i] > widths[best])) best = i;
      });
      if (best < 0) break;
      widths[best]--;
    }

    let x = 2;
    columns.forEach((c, i) => {
      scr.put(x, y, fit(c.title, widths[i]), S.header, scr.cols - 1);
      x += widths[i] + gap;
    });

    const selRow = rows[this.sel[view]];
    const selLine = lines.indexOf(selRow);
    const bodyH = h - 1;
    let top = this.scroll[view];
    if (selLine >= 0) {
      if (selLine < top) top = selLine;
      if (selLine >= top + bodyH) top = selLine - bodyH + 1;
      // keep a section header visible above the first item of a section
      if (selLine - 1 === top - 1 && top > 0 && lines[top - 1]?.section !== undefined) top--;
    }
    top = Math.max(0, Math.min(top, Math.max(0, lines.length - bodyH)));
    this.scroll[view] = top;

    for (let i = 0; i < bodyH && top + i < lines.length; i++) {
      const r = lines[top + i];
      const yy = y + 1 + i;
      if (r.section !== undefined) {
        let sx = scr.put(2, yy, r.section, r.style || S.accentBold);
        if (r.note) sx = scr.put(sx + 2, yy, fit(r.note, scr.cols - sx - 4), S.faint);
        continue;
      }
      const selected = r === selRow;
      if (selected) {
        scr.fill(0, yy, scr.cols, 1, S.sel);
        scr.put(0, yy, '▌', withSel(S.accent, true));
      }
      let cx = 2;
      cells.get(r).forEach(([text, style], ci) => {
        const from = columns[ci].truncate === 'start' ? 'start' : 'end';
        scr.put(cx, yy, fit(text, widths[ci], { from }), withSel(style, selected), scr.cols - 1);
        cx += widths[ci] + gap;
      });
    }
    if (lines.length > bodyH) {
      const pos = `${top + 1}-${Math.min(lines.length, top + bodyH)}/${lines.length}`;
      scr.put(scr.cols - pos.length - 1, y, pos, S.faint);
    }
  }

  drawEmpty(y, lines) {
    lines.forEach(([text, style], i) => this.screen.put(2, y + 1 + i, text, style));
  }

  drawSandboxes(y, h) {
    const rows = this.rowsFor('sandboxes');
    this.syncSelection('sandboxes', rows);
    if (!rows.length) {
      return this.drawEmpty(y, [
        ['No sandboxes yet.', S.dim],
        ['Create one with:  sbx run claude', S.dim],
      ]);
    }
    const now = Date.now();
    this.drawTable('sandboxes', y, h, [
      {
        title: 'SANDBOX', min: 10, max: 34, flex: true,
        cell: (s) => [s.name, S.bold],
      },
      {
        title: '', min: 0, max: 4,
        cell: (s) => { const n = this.pendingCount(s.name); return n ? [`●${n}`, S.yellowBold] : ['', '']; },
      },
      { title: 'AGENT', max: 16, cell: (s) => [s.agent || '-', S.dim] },
      {
        title: 'STATUS', max: 20,
        cell: (s) => s.status === 'running'
          ? [`● running${s.detached ? ' (detached)' : ''}`, S.green]
          : [`○ ${s.status || 'unknown'}`, S.dim],
      },
      {
        title: 'PORTS', max: 30, flex: true, min: 5,
        cell: (s) => [(s.ports || []).map((p) => `${p.host_port}→${p.sandbox_port}`).join(' '), S.accent],
      },
      {
        title: 'WORKSPACE', flex: true, min: 12, truncate: 'start',
        cell: (s) => [(s.workspaces || [])[0] || '-', S.dim],
      },
      { title: 'USED', max: 5, cell: (s) => [ago(s.last_used_at || s.created_at, now), S.faint] },
    ], rows);
    return undefined;
  }

  drawApprovals(y, h) {
    const rows = this.rowsFor('approvals');
    this.syncSelection('approvals', rows);
    const pending = rows.filter((r) => r.kind === 'approval');
    const blocked = rows.filter((r) => r.kind === 'blocked');
    const lines = [
      { section: `PENDING APPROVALS (${pending.length})`, style: pending.length ? S.yellowBold : S.accentBold,
        note: pending.length ? 'a sandbox is waiting for your answer' : 'nothing is waiting for you' },
      ...pending,
      { section: '' },
      { section: `RECENTLY BLOCKED (${blocked.length})`,
        note: blocked.length ? 'denied by policy — add a rule to change that' : 'no blocked requests in the policy log' },
      ...blocked,
    ];
    const now = Date.now();
    this.drawTable('approvals', y, h, [
      { title: 'SANDBOX', max: 30, min: 10, flex: true, cell: (r) => [r.kind === 'approval' ? r.sandbox_name : r.sandbox_id, S.bold] },
      {
        title: 'REQUEST', min: 16, flex: true,
        cell: (r) => r.kind === 'approval' ? [r.title, S.yellow] : [r.host, ''],
      },
      {
        title: 'DETAIL', min: 10, flex: true,
        cell: (r) => r.kind === 'approval'
          ? [String(r.detail || '').replace(/\s*\n\s*/g, ' · '), S.dim]
          : [`${r.count}× · ${r.reason || r.rule || 'blocked'}`, S.dim],
      },
      { title: 'AGE', max: 5, cell: (r) => [ago(r.kind === 'approval' ? r.created_at : r.last_seen, now), S.faint] },
    ], rows, lines);
  }

  drawPorts(y, h) {
    const rows = this.rowsFor('ports');
    this.syncSelection('ports', rows);
    if (!rows.length) {
      return this.drawEmpty(y, [
        ['No ports are forwarded.', S.dim],
        ['', ''],
        ['Press n to forward a sandbox port to this machine,', S.dim],
        ['for example to open a web server running in a sandbox in your browser.', S.dim],
      ]);
    }
    this.drawTable('ports', y, h, [
      { title: 'SANDBOX', max: 30, min: 10, flex: true, cell: (r) => [r.sandbox, S.bold] },
      { title: 'ON THIS MACHINE', max: 28, cell: (r) => [`${r.host_ip.includes(':') ? `[${r.host_ip}]` : r.host_ip}:${r.host_port}`, S.accent] },
      { title: '', cell: () => ['→', S.faint] },
      { title: 'SANDBOX PORT', cell: (r) => [String(r.sandbox_port), ''] },
      { title: 'PROTO', cell: (r) => [r.protocol, S.dim] },
      { title: 'URL', flex: true, min: 8, cell: (r) => [portUrl(r) || '-', S.green] },
    ], rows);
    return undefined;
  }

  // ───────────────────────────── modal drawing ─────────────────────────────

  modalBox(w, h, title, style = S.accent) {
    const scr = this.screen;
    w = Math.min(w, scr.cols - 2);
    h = Math.min(h, scr.rows - 2);
    const x = Math.max(0, Math.floor((scr.cols - w) / 2));
    const y = Math.max(0, Math.floor((scr.rows - h) / 2));
    scr.box(x, y, w, h, style, title);
    return { x: x + 3, y: y + 1, w: w - 6, right: x + w - 2, bottom: y + h - 1 };
  }

  hints(x, y, pairs, maxX) {
    const scr = this.screen;
    for (const [key, label] of pairs) {
      x = scr.put(x, y, key, S.key, maxX);
      x = scr.put(x + 1, y, label, S.dim, maxX) + 3;
    }
  }

  drawModal() {
    const m = this.modal;
    const scr = this.screen;
    if (m.type === 'confirm') {
      const w = Math.max(44, ...m.lines.map((l) => strWidth(l) + 8));
      const b = this.modalBox(w, m.lines.length + 6, m.title, m.danger ? S.red : S.accent);
      m.lines.forEach((l, i) => scr.put(b.x, b.y + 1 + i, fit(l, b.w), i === 0 ? S.bold : S.dim));
      this.hints(b.x, b.y + m.lines.length + 3, m.danger ? [['y', 'yes'], ['n', 'no']] : [['enter', 'yes'], ['esc', 'no']], b.right);
      return;
    }
    if (m.type === 'menu') {
      const inner = Math.max(
        40,
        strWidth(m.subtitle),
        ...m.items.map((it) => strWidth(it.label) + strWidth(it.hint) + 8),
      );
      const b = this.modalBox(inner + 6, m.items.length + 7, m.title);
      scr.put(b.x, b.y + 1, fit(m.subtitle, b.w), S.dim);
      m.items.forEach((it, i) => {
        const yy = b.y + 3 + i;
        const selected = i === m.sel;
        if (selected) scr.fill(b.x - 1, yy, b.w + 2, 1, S.sel);
        let x = scr.put(b.x, yy, `${i + 1}`, withSel(S.faint, selected), b.right);
        x = scr.put(x + 1, yy, it.label, withSel(S.bold, selected), b.right);
        if (it.hint) scr.put(x + 2, yy, fit(it.hint, Math.max(0, b.right - x - 3)), withSel(S.dim, selected), b.right);
      });
      this.hints(b.x, b.y + m.items.length + 4, [['enter', 'choose'], ['esc', 'cancel']], b.right);
      return;
    }
    if (m.type === 'help') {
      const lines = [
        ['Everywhere', null],
        ['1 2 3 · tab · ← →', 'switch view'],
        ['↑ ↓ · j k · pgup pgdn', 'move selection'],
        ['r', 'refresh now (auto-refreshes every few seconds)'],
        ['q · ctrl+c', 'quit'],
        ['', ''],
        ['Sandboxes', null],
        ['enter', 'attach to the agent (sbx run --name)'],
        ['e', 'open a shell in the sandbox'],
        ['p', 'forward a port to this machine'],
        ['s · x', 'stop · remove'],
        ['', ''],
        ['Approvals', null],
        ['a · d', 'allow · deny/dismiss the selected request'],
        ['enter', 'show every option the request offers'],
        ['A · D', 'allow all · dismiss all pending requests'],
        ['a · d on a blocked host', 'add an allow / deny rule'],
        ['', ''],
        ['Ports', null],
        ['n', 'forward a new port'],
        ['o · enter', 'open in browser'],
        ['c · d', 'copy URL · unpublish'],
      ];
      const b = this.modalBox(70, lines.length + 4, 'Keys');
      lines.forEach(([k, label], i) => {
        if (label === null) scr.put(b.x, b.y + 1 + i, k, S.accentBold, b.right);
        else {
          scr.put(b.x + 1, b.y + 1 + i, k, S.key, b.right);
          scr.put(b.x + 26, b.y + 1 + i, label, S.dim, b.right);
        }
      });
      return;
    }
    this.drawForm(m);
  }

  drawForm(f) {
    const scr = this.screen;
    const b = this.modalBox(74, 19, 'Forward a port to this machine');
    const sb = this.sandboxes.find((s) => s.name === f.sandbox);
    const running = sb?.status === 'running';
    const labelW = 16;
    const vx = b.x + labelW;
    let y = b.y + 1;

    const label = (i, text) => scr.put(b.x, y, text, f.field === i ? S.accentBold : S.dim);
    const selector = (i, value) => {
      const active = f.field === i;
      let x = scr.put(vx, y, active ? '‹ ' : '  ', S.accent, b.right);
      x = scr.put(x, y, value, active ? S.bold : '', b.right);
      return scr.put(x, y, active ? ' ›' : '  ', S.accent, b.right);
    };
    const input = (i, value, placeholder) => {
      const active = f.field === i;
      const w = 9;
      scr.fill(vx, y, w, 1, active ? S.fieldActive : S.field);
      if (value) scr.put(vx + 1, y, value, active ? S.fieldActive : S.field);
      else if (placeholder) scr.put(vx + 1, y, fit(placeholder, w - 2), active ? S.fieldActive : withSel(S.faint, false) + ';48;5;236');
      if (active && !f.submitting) scr.put(vx + 1 + value.length, y, '▏', S.fieldActive);
      return vx + w;
    };
    const hint = (x, text, style = S.faint) => scr.put(x + 2, y, fit(text, Math.max(0, b.right - x - 3)), style, b.right);

    label(0, 'Sandbox');
    hint(selector(0, fit(f.sandbox, 30)), running ? '● running' : `○ ${sb?.status || 'unknown'}`, running ? S.green : S.dim);
    y += 2;

    label(1, 'Sandbox port');
    const listening = this.listeningFor(f.sandbox);
    hint(
      input(1, f.sandboxPort, ''),
      listening.length
        ? `listening: ${listening.join(' ')}${f.field === 1 ? '  (← → to pick)' : ''}`
        : running ? 'the port your server listens on inside the sandbox' : 'the port your server listens on',
      listening.length ? S.green : S.faint,
    );
    y += 2;

    label(2, 'Host port');
    hint(input(2, f.hostPort, f.sandboxPort || 'same'), f.hostPort === '0' ? 'sbx picks a free port' : 'empty = same port · 0 = any free port');
    y += 2;

    label(3, 'Protocol');
    hint(selector(3, f.protocol), PROTO_HINT[f.protocol] || '');
    y += 2;

    label(4, 'Reachable from');
    hint(selector(4, BINDS[f.bind].label), f.bind === 1 ? 'other devices on your network can connect!' : '', S.yellow);
    y += 2;

    label(5, 'Open browser');
    scr.put(vx, y, f.open ? '[x]' : '[ ]', f.field === 5 ? S.accentBold : '');
    scr.put(vx + 4, y, 'when published', S.dim, b.right);
    y += 2;

    let spec = null;
    let specError = '';
    try { spec = this.formSpec(f); } catch (e) { specError = e.message; }
    if (spec) {
      let x = scr.put(b.x, y, '$ ', S.faint);
      scr.put(x, y, fit(`sbx ports ${f.sandbox} --publish ${spec}`, b.right - x - 1), S.accent, b.right);
    } else {
      scr.put(b.x, y, f.sandboxPort ? fit(specError, b.w) : 'Type the sandbox port to forward.', S.dim, b.right);
    }
    y += 1;

    const hostPort = parsePort(f.hostPort === '' ? f.sandboxPort : f.hostPort);
    const clash = hostPort && this.portRows().find((r) => r.host_port === hostPort);
    if (f.error) scr.put(b.x, y, fit(`✗ ${f.error}`, b.w), S.red, b.right);
    else if (f.submitting) scr.put(b.x, y, `${SPINNER[this.spin % SPINNER.length]} Publishing…${running ? '' : ' (starting the sandbox first)'}`, S.accent, b.right);
    else if (clash) scr.put(b.x, y, fit(`! host port ${hostPort} is already forwarded to ${clash.sandbox}:${clash.sandbox_port}`, b.w), S.yellow, b.right);
    else if (!running) scr.put(b.x, y, '! this sandbox is stopped — publishing will start it', S.yellow, b.right);
    y += 2;

    this.hints(b.x, y, [['enter', 'publish'], ['tab ↑↓', 'next field'], ['← →', 'change'], ['esc', 'cancel']], b.right);
  }
}
