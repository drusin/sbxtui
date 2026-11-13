> 🤖 100% vibe-coded 🤖

# sbxtui

A terminal dashboard for [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`).
It is a from-scratch alternative to the closed-source `sbx tui`, with two additions:

- **Approvals** — all pending policy requests from every sandbox in one list, allowed or denied with
  one key. Recently blocked hosts can be turned into allow or deny rules.
- **Ports** — a form to forward a sandbox port to your machine, then open it in your browser.

It drives the `sbx` CLI and needs only `sbx` and Node.js 18+. No dependencies, no build step.

## Run

```sh
sbxtui.cmd                 # Windows
./sbxtui                   # Linux / macOS
node bin/sbxtui.mjs        # anywhere
```

Use a real console such as Windows Terminal. In Git Bash's own window, run `winpty node bin/sbxtui.mjs`.

Options: `--view sandboxes|approvals|ports`, `--interval SECS`, `--no-bell`, `--sbx PATH`.

## Keys

Press `?` in the app for the full list.

| View | Keys |
| --- | --- |
| All | `1` `2` `3` or `tab` switch view · `↑` `↓` move · `r` refresh · `q` quit |
| Sandboxes | `enter` attach · `e` shell · `p` forward a port · `s` stop · `x` remove |
| Approvals | `a` allow · `d` deny · `enter` all options · `A` / `D` allow / dismiss all |
| Ports | `n` new forward · `o` open in browser · `c` copy URL · `d` unpublish |

In the port form, type the sandbox port and press `enter`. The host port defaults to the same number;
`0` lets `sbx` pick a free one.

## Development

```sh
npm test
```

| File | Purpose |
| --- | --- |
| `bin/sbxtui.mjs` | terminal setup and key decoding |
| `src/app.mjs` | state, key handling, rendering |
| `src/sbx.mjs` | wrapper around the `sbx` CLI |
| `src/sbx-worker.mjs` | runs `sbx` off the UI thread so the interface stays responsive |
| `src/term.mjs` | screen buffer that repaints only changed rows |
