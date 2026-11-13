#!/usr/bin/env node
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { App } from '../src/app.mjs';
import { Sbx } from '../src/sbx.mjs';
import { ansi } from '../src/term.mjs';

const HELP = `sbxtui — a terminal dashboard for Docker Sandboxes (sbx)

Usage:
  sbxtui [options]

Options:
  --sbx PATH        Path to the sbx binary (default: sbx on PATH, or $SBX_BIN)
  --interval SECS   Refresh interval in seconds (default: 2)
  --view NAME       Start on: sandboxes, approvals or ports
  --no-bell         Do not ring the terminal bell when a new approval arrives
  -h, --help        Show this help

Press ? inside the app for the key bindings.
`;

function parseArgs(argv) {
  const o = { interval: 2, bell: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) fail(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '-h' || a === '--help') { process.stdout.write(HELP); process.exit(0); }
    else if (a === '--sbx') o.bin = next();
    else if (a === '--interval') {
      o.interval = Number(next());
      if (!(o.interval >= 0.5)) fail('--interval must be a number of seconds, at least 0.5');
    }
    else if (a === '--view') {
      o.view = next();
      if (!['sandboxes', 'approvals', 'ports'].includes(o.view)) fail('--view must be sandboxes, approvals or ports');
    }
    else if (a === '--no-bell') o.bell = false;
    else fail(`Unknown option: ${a}`);
  }
  return o;
}

function fail(msg) {
  process.stderr.write(`sbxtui: ${msg}\n\n${HELP}`);
  process.exit(2);
}

const SPECIAL = new Set([
  'up', 'down', 'left', 'right', 'return', 'enter', 'escape', 'tab', 'backspace', 'delete',
  'pageup', 'pagedown', 'home', 'end', 'space',
]);

function normalizeKey(str, key = {}) {
  let name = key.name;
  if (name === 'enter') name = 'return';
  if (key.ctrl && name) return `ctrl+${name}`;
  if (name === 'tab' && key.shift) return 'shift+tab';
  if (name && SPECIAL.has(name)) return name;
  return str || name || '';
}

const opts = parseArgs(process.argv.slice(2));
const { stdin, stdout } = process;

if (!stdin.isTTY || !stdout.isTTY) {
  process.stderr.write(
    'sbxtui needs an interactive terminal.\n' +
      (process.platform === 'win32'
        ? 'In Git Bash (mintty) run it through winpty:  winpty node bin/sbxtui.mjs\n'
        : ''),
  );
  process.exit(1);
}

const sbx = new Sbx({ bin: opts.bin });
const io = {
  write: (s) => stdout.write(s),
  get columns() { return stdout.columns; },
  get rows() { return stdout.rows; },
};

function enterScreen() {
  stdin.setRawMode(true);
  stdin.resume();
  stdout.write(ansi.enterAlt + ansi.hideCursor + ansi.clear);
}

function leaveScreen() {
  stdout.write(ansi.reset + ansi.showCursor + ansi.leaveAlt);
  if (stdin.isTTY) stdin.setRawMode(false);
}

let quitting = false;
function quit(code = 0) {
  if (quitting) return;
  quitting = true;
  app.stop();
  leaveScreen();
  process.exit(code);
}

/** Give the terminal to a child process (an agent session, a shell), then take it back. */
async function suspend(run) {
  leaveScreen();
  stdin.pause();
  const { bin, args } = run();
  stdout.write(`\x1b[2m$ ${bin} ${args.join(' ')}\x1b[0m\n`);
  const started = Date.now();
  const code = await new Promise((resolve) => {
    const child = spawn(bin, args, { stdio: 'inherit' });
    child.on('error', (e) => { process.stderr.write(`${e.message}\n`); resolve(1); });
    child.on('exit', (c) => resolve(c ?? 1));
  });
  stdin.setRawMode(true);
  stdin.resume();
  // A command that failed straight away printed its reason; let the user read it.
  if (code !== 0 && Date.now() - started < 15000) {
    stdout.write('\n\x1b[2mPress any key to return to sbxtui…\x1b[0m');
    await new Promise((resolve) => stdin.once('data', resolve));
  }
  stdout.write(ansi.enterAlt + ansi.hideCursor + ansi.clear);
  return code;
}

const app = new App({ sbx, io, interval: opts.interval * 1000, bell: opts.bell, hooks: { quit, suspend } });
if (opts.view) app.view = opts.view;

readline.emitKeypressEvents(stdin, { escapeCodeTimeout: 50 });
stdin.on('keypress', (str, key) => {
  if (app.suspended) return;
  const k = normalizeKey(str, key);
  if (k) app.key(k, str && str.length === 1 && str >= ' ' ? str : '');
});
stdout.on('resize', () => app.resize(stdout.columns, stdout.rows));
process.on('SIGINT', () => quit(0));
process.on('SIGTERM', () => quit(0));
process.on('uncaughtException', (e) => {
  leaveScreen();
  console.error(e);
  process.exit(1);
});

enterScreen();
app.start();
