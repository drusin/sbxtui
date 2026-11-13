// Runs sbx commands off the UI thread. On Windows, starting a process blocks the
// calling thread for hundreds of milliseconds (CreateProcess plus antivirus
// scanning), which would freeze key handling if done on the main thread.
import { parentPort } from 'node:worker_threads';
import { execFile } from 'node:child_process';

parentPort.on('message', ({ id, bin, args, timeout }) => {
  execFile(
    bin,
    args,
    { timeout, windowsHide: true, maxBuffer: 32 * 1024 * 1024, encoding: 'utf8' },
    (err, stdout, stderr) => {
      parentPort.postMessage({
        id,
        stdout,
        stderr,
        error: err ? { code: err.code, killed: !!err.killed, message: err.message } : null,
      });
    },
  );
});
