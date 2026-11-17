# CyberShield: Intelligent Cyber Threat Log Analyzer (web edition)

The original C program (`cybershield.c`) compiled to WebAssembly and run in the
browser. Nothing is rewritten: the page runs the same C code and shows its
terminal menu.

## Deploy on Vercel

This is a static site. There is no build step.

1. Put this folder in a GitHub repo (or drag the folder into the Vercel dashboard).
2. In Vercel: **Add New > Project**, import the repo.
3. Framework Preset: **Other**. Build Command: leave empty. Output Directory: leave as `.` (root).
4. Deploy. The site's root URL shows the CyberShield terminal.

If the repo holds this folder inside another one, set **Root Directory** to this folder.

## Files

| File | Purpose |
|------|---------|
| `index.html` | The page (terminal, menu buttons, CSV upload) |
| `runner.js` | Runs the WebAssembly program with a WASI shim |
| `cybershield.wasm` | The compiled C program |
| `cybershield.c` | The C source (linked list, queue, hash table, BST, stack) |
| `sample_logs.csv` | Built-in sample data |
| `vendor/` | `@bjorn3/browser_wasi_shim` 0.4.2 (MIT or Apache-2.0) |

## How it works

A browser cannot pause a program while it waits for keyboard input. So after
every line you type, the page re-runs the program from the start with all lines
typed so far as its input. The program is deterministic, so it reaches the same
state and stops at the next prompt; the page shows only the new output.
Logs added with a blank timestamp use the current time of each re-run, so type
a timestamp if you want exact values.

## Run natively

```
gcc -Wall -Wextra -o cybershield cybershield.c
./cybershield
```

## Rebuild the .wasm after editing the C code

Needs `clang` with the `wasm32` target, `wasm-ld`, and the WASI sysroot and
`libclang_rt.builtins-wasm32.a` from a wasi-sdk release (v24 was used):

```
clang --target=wasm32-wasi --sysroot=<wasi-sysroot> -O2 -nodefaultlibs \
  -o cybershield.wasm cybershield.c -lc <path>/libclang_rt.builtins-wasm32.a
```

Alternatively, with Emscripten or the full wasi-sdk installed:
`/opt/wasi-sdk/bin/clang -O2 -o cybershield.wasm cybershield.c`

## Note

The logs are simulated. Alerts are suspicious patterns that need investigation,
not proof that any IP or user is malicious.
