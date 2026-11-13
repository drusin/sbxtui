// Minimal cell-buffer terminal renderer. No dependencies.

const ESC = '\x1b[';

export const ansi = {
  enterAlt: '\x1b[?1049h',
  leaveAlt: '\x1b[?1049l',
  hideCursor: '\x1b[?25l',
  showCursor: '\x1b[?25h',
  clear: '\x1b[2J\x1b[H',
  syncStart: '\x1b[?2026h',
  syncEnd: '\x1b[?2026l',
  reset: '\x1b[0m',
};

const noColor = !!process.env.NO_COLOR;

// Styles are SGR parameter strings.
export const S = {
  none: '',
  bold: '1',
  dim: noColor ? '2' : '38;5;245',
  faint: noColor ? '2' : '38;5;240',
  accent: noColor ? '1' : '38;5;39',
  accentBold: noColor ? '1' : '1;38;5;39',
  green: noColor ? '' : '38;5;78',
  yellow: noColor ? '1' : '38;5;221',
  yellowBold: noColor ? '1' : '1;38;5;221',
  red: noColor ? '1' : '38;5;203',
  redBold: noColor ? '1' : '1;38;5;203',
  header: noColor ? '1' : '1;38;5;250',
  tabActive: noColor ? '1;7' : '1;38;5;16;48;5;39',
  tab: noColor ? '' : '38;5;250',
  badge: noColor ? '1;7' : '1;38;5;16;48;5;221',
  sel: noColor ? '7' : '48;5;237',
  field: noColor ? '4' : '48;5;236',
  fieldActive: noColor ? '7' : '48;5;24;38;5;231',
  key: noColor ? '1' : '1;38;5;117',
};

/** Combine a style with the selection background. */
export function withSel(style, selected) {
  if (!selected) return style;
  if (noColor) return '7';
  // drop any existing background, add selection background
  const parts = style ? style.split(';') : [];
  const out = [];
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '48') { i += 2; continue; }
    out.push(parts[i]);
  }
  out.push('48;5;237');
  return out.join(';');
}

export function charWidth(cp) {
  if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0)) return 0;
  if (cp >= 0x300 && cp <= 0x36f) return 0; // combining
  if (cp === 0x200b || cp === 0xfe0f) return 0;
  if (
    (cp >= 0x1100 && cp <= 0x115f) ||
    (cp >= 0x2e80 && cp <= 0xa4cf) ||
    (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) ||
    (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f300 && cp <= 0x1faff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) return 2;
  return 1;
}

export function strWidth(s) {
  let w = 0;
  for (const ch of String(s)) w += charWidth(ch.codePointAt(0));
  return w;
}

/** Truncate to a display width, adding an ellipsis when cut. */
export function fit(s, width, { ellipsis = '…', from = 'end' } = {}) {
  s = String(s ?? '');
  if (width <= 0) return '';
  if (strWidth(s) <= width) return s;
  const chars = [...s];
  if (from === 'start') {
    let out = '';
    let w = strWidth(ellipsis);
    for (let i = chars.length - 1; i >= 0; i--) {
      const cw = charWidth(chars[i].codePointAt(0));
      if (w + cw > width) break;
      out = chars[i] + out;
      w += cw;
    }
    return ellipsis + out;
  }
  let out = '';
  let w = strWidth(ellipsis);
  for (const ch of chars) {
    const cw = charWidth(ch.codePointAt(0));
    if (w + cw > width) break;
    out += ch;
    w += cw;
  }
  return out + ellipsis;
}

export class Screen {
  constructor(cols, rows) {
    this.prev = [];
    this.resize(cols, rows);
  }

  resize(cols, rows) {
    this.cols = Math.max(1, cols | 0);
    this.rows = Math.max(1, rows | 0);
    this.prev = []; // force full repaint
    this.clear();
  }

  clear() {
    this.ch = new Array(this.rows);
    this.st = new Array(this.rows);
    for (let y = 0; y < this.rows; y++) {
      this.ch[y] = new Array(this.cols).fill(' ');
      this.st[y] = new Array(this.cols).fill('');
    }
  }

  /** Write text at x,y; clipped to [x, maxX). Returns the x after the text. */
  put(x, y, text, style = '', maxX = this.cols) {
    if (y < 0 || y >= this.rows) return x;
    maxX = Math.min(maxX, this.cols);
    const row = this.ch[y];
    const srow = this.st[y];
    for (const c of String(text ?? '')) {
      const w = charWidth(c.codePointAt(0));
      if (w === 0) continue;
      if (x + w > maxX) break;
      if (x >= 0) {
        row[x] = c;
        srow[x] = style;
        if (w === 2) {
          row[x + 1] = '';
          srow[x + 1] = style;
        }
      }
      x += w;
    }
    return x;
  }

  fill(x, y, w, h, style = '', char = ' ') {
    for (let yy = Math.max(0, y); yy < Math.min(this.rows, y + h); yy++) {
      for (let xx = Math.max(0, x); xx < Math.min(this.cols, x + w); xx++) {
        this.ch[yy][xx] = char;
        this.st[yy][xx] = style;
      }
    }
  }

  /** Apply a style to an existing region, keeping its characters. */
  restyle(x, y, w, fn) {
    if (y < 0 || y >= this.rows) return;
    for (let xx = Math.max(0, x); xx < Math.min(this.cols, x + w); xx++) {
      this.st[y][xx] = fn(this.st[y][xx]);
    }
  }

  hline(x, y, w, style = S.faint, char = '─') {
    this.fill(x, y, w, 1, style, char);
  }

  box(x, y, w, h, style = S.accent, title = '') {
    if (w < 2 || h < 2) return;
    this.fill(x, y, w, h, '');
    this.put(x, y, '╭' + '─'.repeat(w - 2) + '╮', style);
    for (let yy = y + 1; yy < y + h - 1; yy++) {
      this.put(x, yy, '│', style);
      this.put(x + w - 1, yy, '│', style);
    }
    this.put(x, y + h - 1, '╰' + '─'.repeat(w - 2) + '╯', style);
    if (title) this.put(x + 2, y, ` ${fit(title, w - 6)} `, S.accentBold);
  }

  rowString(y) {
    let out = '';
    let cur = null;
    const row = this.ch[y];
    const srow = this.st[y];
    for (let x = 0; x < this.cols; x++) {
      if (srow[x] !== cur) {
        cur = srow[x];
        out += cur ? `${ESC}0;${cur}m` : `${ESC}0m`;
      }
      out += row[x];
    }
    return out + `${ESC}0m`;
  }

  /** Plain-text dump (for tests and --dump). */
  toText() {
    const lines = [];
    for (let y = 0; y < this.rows; y++) lines.push(this.ch[y].join('').replace(/\s+$/, ''));
    return lines.join('\n');
  }

  /** Write only the rows that changed since the last flush. */
  flush(out) {
    let buf = '';
    for (let y = 0; y < this.rows; y++) {
      const s = this.rowString(y);
      if (this.prev[y] !== s) {
        buf += `${ESC}${y + 1};1H${s}`;
        this.prev[y] = s;
      }
    }
    if (buf) out.write(ansi.syncStart + buf + ansi.syncEnd);
  }
}
