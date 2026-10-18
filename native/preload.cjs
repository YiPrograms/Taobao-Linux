'use strict';

const Module = require('node:module');
const path = require('node:path');

const replacements = new Map([
  ['@ali/electron-process-manager', 'linux-process-manager.cjs'],
  ['@ali/pc-security-bodyguard', 'linux-security.cjs'],
]);

const originalLoad = Module._load;

Module._load = function (request, parent, isMain) {
  const replacement = process.platform === 'linux' && replacements.get(request);
  const target = replacement ? path.join(__dirname, replacement) : request;

  return originalLoad.call(this, target, parent, isMain);
};
