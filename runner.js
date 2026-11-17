// Runs the real CyberShield C program (compiled to WebAssembly/WASI).
//
// The program reads its input with fgets(), which cannot block inside a
// browser. So each time the user enters a line, we re-run the program from
// the start with ALL lines typed so far as stdin. The C program is
// deterministic, so it reaches the same state and then stops (end of input)
// at the next prompt. The page shows only the output that is new.

import { WASI, File, OpenFile, PreopenDirectory } from "./vendor/index.js";

export function runOnce(wasmModule, stdinText, files) {
  const enc = new TextEncoder();
  const stdin = new OpenFile(new File(enc.encode(stdinText)));
  const stdout = new OpenFile(new File([]));
  const stderr = new OpenFile(new File([]));

  const dir = new Map();
  for (const [name, data] of files) dir.set(name, new File(data));
  const root = new PreopenDirectory(".", dir);

  const wasi = new WASI(["cybershield"], [], [stdin, stdout, stderr, root], { debug: false });
  const instance = new WebAssembly.Instance(wasmModule, {
    wasi_snapshot_preview1: wasi.wasiImport,
  });
  wasi.start(instance);

  const dec = new TextDecoder();
  const out = new Map();
  for (const [name, node] of root.dir.contents) {
    if (node.data) out.set(name, node.data);
  }
  return { output: dec.decode(stdout.file.data), files: out };
}
