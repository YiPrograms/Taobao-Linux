'use strict';

const Module = require('node:module');
const os = require('node:os');

const interfaces = Object.values(os.networkInterfaces()).flat();

if (interfaces.some((address) => !address.internal)) {
  throw new Error('Smoke test requires an isolated network namespace');
}

let app;
let securityObserved = false;
let exiting = false;
const observed = new Set();

function record(event) {
  observed.add(event);
  process.stderr.write(`[taobao-linux] ${event}\n`);

  if (app && observed.size === 3 && !exiting) {
    exiting = true;
    setTimeout(() => app.exit(0), 500);
  }
}

// Electron installs its built-in module after NODE_OPTIONS preloads run.
const originalLoad = Module._load;

Module._load = function (request, parent, isMain) {
  const loaded = originalLoad.call(this, request, parent, isMain);

  if (request.endsWith('/native/linux-security.cjs') && !securityObserved) {
    securityObserved = true;
    loaded.once('initialized', () => record('security initialized'));
    loaded.once('securityFactorsReceived', () => record('security factors generated'));
  }

  if (request === 'electron' && loaded.app && !app) {
    app = loaded.app;

    app.on('browser-window-created', (_event, window) => {
      window.webContents.on('did-finish-load', () => {
        if (window.webContents.getURL().startsWith('file://')) {
          record('renderer loaded');
        }
      });
    });
  }

  return loaded;
};
