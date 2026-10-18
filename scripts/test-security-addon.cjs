'use strict';

// Offline interoperability tests: never launch the client or contact Taobao.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const dataDirectory = process.env.TAOBAO_HOME;
const addonPath = path.join(dataDirectory, 'native/security-bodyguard/my_addon.node');
const { MyAddon } = require(addonPath);

if (process.env.TAOBAO_TEST_SECRET_SERVICE !== '1') {
  throw new Error('Run sh scripts/test-security-addon.sh to isolate the keyring');
}

function testPlatform(native) {
  const platform = native.getPlatformInfo();
  assert.equal(platform.os, 'Linux');
  assert.equal(platform.arch, 'x86_64');
  assert.ok(platform.memoryBytes > 0);
  assert.equal(platform.executable, fs.readlinkSync('/proc/self/exe'));
  const collection = native.getLinuxCollectionInfo();
  assert.equal(collection.platform, 'linux');
  assert.equal(collection.appleTrustAnchor, false);
  assert.equal(collection.appleTeamId, null);
  assert.equal(collection.fields['14'].value, 'Linux');
  assert.equal(collection.fields['17'].value, 'x86_64');
  assert.equal(collection.fields['184'].value, '1');
  assert.equal(collection.fields['56'].available, false);
  assert.equal(collection.fields['181'], undefined); // Unmapped IDs are not invented.
}

function testEncryption(native) {
  // Includes Unicode, embedded NUL, multiple AES blocks, and the maximum raw
  // plaintext size; exercise genuine vendor key resources for both algorithms.
  const inputs = ['a', 'Linux 原生安全元件 🐧', 'zero\0inside', 'x'.repeat(262144)];
  let roundTrips = 0;
  for (const method of [1, 2]) {
    for (const input of inputs) {
      const encoded = native.staticEncrypt(method, input);
      assert.equal(encoded.success, true);
      assert.equal(encoded.errorCode, 0);
      const decoded = native.staticDecrypt(method, encoded.output);
      assert.deepEqual(decoded, { success: true, errorCode: 0, output: input });
      const fromBase64 = native.staticEncrypt(
        method,
        Buffer.from(input).toString('base64'),
        true,
        true,
      );
      assert.equal(fromBase64.success, true);
      const base64Plain = native.staticDecrypt(method, fromBase64.output, true, true);
      assert.equal(base64Plain.success, true);
      assert.equal(Buffer.from(base64Plain.output, 'base64').toString(), input);
      roundTrips += 2;
    }
  }

  return roundTrips;
}

function testSignaturesAndValidation(native) {
  for (const method of [1, 2, 3]) {
    const signed = native.urlSign('offline-local-interop-test', method);
    const repeated = native.urlSign('offline-local-interop-test', method);
    assert.equal(signed.success, true);
    assert.equal(signed.errorCode, 0);
    assert.ok(signed.output.length >= 32);
    assert.deepEqual(repeated, signed);
    assert.notEqual(native.urlSign('different-offline-input', method).output, signed.output);
  }
  assert.throws(() => native.staticEncrypt(3, 'x'), /method/);
  assert.throws(() => native.staticEncrypt(1.5, 'x'), /method/);
  assert.throws(() => native.urlSign('x', 'invalid'), /method/);
  assert.throws(() => native.storeWrite('x', 'value\0with-nul'), /NUL/);
  assert.throws(() => native.storeRead(''), /nonempty/);
  assert.throws(() => native.getSecurityFactors('{}'), /not initialized/);
  native.cleanupSecurity();
  assert.equal(native.getCapabilities().staticCrypto, false);
  assert.throws(() => native.staticEncrypt(1, 'x'), /initializeCrypto/);
}

async function loadWrapper() {
  // Exercise the module hook used by Electron without launching the app.
  require(path.join(root, 'native/preload.cjs'));
  const resolveFromApp = require('node:module').createRequire(
    path.join(dataDirectory, 'app-src/package.json'),
  );
  const wrapper = resolveFromApp('@ali/pc-security-bodyguard');
  assert.equal(wrapper.getStatus().hasNativeAddon, true);
  assert.equal(wrapper.isInitialized(), false);
  await assert.rejects(
    wrapper.getSecurityFactors('https://example.invalid/offline'),
    /not initialized/,
  );

  return wrapper;
}

async function testSecurityFactors(native, wrapper) {
  assert.equal(native.initializeSecurity(''), true);
  assert.equal(await wrapper.initializeSecurity(), true);
  assert.equal(wrapper.isInitialized(), true);
  const parameters = {
    api: 'example.invalid/offline',
    urlmd5: '900150983cd24fb0d6963f7d28e17f72',
    timestamp: '1792288800',
  };
  const factorResult = native.getSecurityFactors(JSON.stringify(parameters));
  assert.equal(factorResult.success, true);
  assert.equal(factorResult.errorCode, 0);
  assert.equal(factorResult.status.umidSource, 'local-fallback');
  assert.equal(factorResult.status.serverEnrolled, false);
  assert.equal(factorResult.status.serverAcceptance, 'unverified');
  assert.equal(factorResult.status.appleTrustAnchor, false);
  const factors = JSON.parse(factorResult.result);
  const canonical =
    '&&&35118605&900150983cd24fb0d6963f7d28e17f72&1792288800&example.invalid/offline&1.0&&&&&&&&&&&&&&';
  assert.equal(factors['pctb-x-sign'], native.urlSign(canonical).output);
  assert.match(factors['pctb-x-umt'], /^[0-9A-Za-z]{32}$/);
  assert.ok(factors['pctb-x-mini-wua'].length > 100);
  assert.equal(factors['pctb-x-api'], parameters.api);
  assert.equal(factors['x-bx-env'], 'web');
  let received = false;
  wrapper.once('securityFactorsReceived', () => {
    received = true;
  });
  const wrapped = await wrapper.getSecurityFactors('https://example.invalid/offline?q=台灣');
  assert.equal(wrapped.success, true);
  assert.equal(received, true);
  assert.equal(wrapper.getStatus().security.serverEnrolled, false);
  assert.throws(() => native.getSecurityFactors('{}'), /missing string/);
  assert.throws(
    () => native.getSecurityFactors(JSON.stringify({ ...parameters, urlmd5: 'bad' })),
    /digest/,
  );
  assert.throws(
    () => native.getSecurityFactors(JSON.stringify({ ...parameters, api: 'bad\r\nheader' })),
    /parameter/,
  );

  // Reload the same local identity in an independent process. Only a digest
  // leaves the private test process; never print a live account token.
  const persisted = spawnSync(
    process.execPath,
    [
      '-e',
      `
    const {MyAddon} = require(${JSON.stringify(addonPath)});
    const x = new MyAddon(${JSON.stringify(`offline-test-${process.pid}`)});
    x.initializeSecurity();
    const result = JSON.parse(x.getSecurityFactors(${JSON.stringify(JSON.stringify(parameters))}).result);
    process.stdout.write(require('node:crypto').createHash('sha256').update(result['pctb-x-umt']).digest('hex'));
  `,
    ],
    { env: process.env, encoding: 'utf8', timeout: 15000 },
  );
  assert.equal(persisted.status, 0, persisted.stderr);
  assert.equal(
    persisted.stdout,
    crypto.createHash('sha256').update(factors['pctb-x-umt']).digest('hex'),
  );
}

function testStorage() {
  const first = new MyAddon(`test-first-${process.pid}`);
  const second = new MyAddon(`test-second-${process.pid}`);
  assert.equal(first.testStorage(), true);
  try {
    assert.deepEqual(first.storeRead('key'), { success: false, value: '' });
    assert.equal(first.storeWrite('key', '測試 value'), true);
    assert.equal(first.storeWrite('key', 'do not replace'), false);
    assert.equal(first.storeRead('key').value, '測試 value');
    assert.equal(first.storeWrite('key', 'replacement', true), true);
    assert.equal(second.storeWrite('key', 'second namespace'), true);
    assert.equal(first.storeDeleteDatabase(), true);
    assert.equal(first.storeRead('key').success, false);
    assert.equal(second.storeRead('key').value, 'second namespace');
    assert.equal(second.storeDelete('key'), true);
    assert.equal(second.storeRead('key').success, false);
    assert.equal(second.storeWrite('empty', ''), true);
    assert.deepEqual(second.storeRead('empty'), { success: true, value: '' });
  } finally {
    first.storeDeleteDatabase();
    second.storeDeleteDatabase();
  }
}

function testUnavailableService() {
  // No-service errors must propagate instead of silently using plaintext files.
  const unavailable = spawnSync(
    process.execPath,
    [
      '-e',
      `
    const assert = require('node:assert/strict');
    const {MyAddon} = require(${JSON.stringify(addonPath)});
    assert.throws(() => new MyAddon('offline-no-bus').storeRead('key'), /Secret Service/);
    const failed = new MyAddon('offline-no-bus');
    assert.throws(() => failed.initializeSecurity(), /Secret Service/);
    assert.equal(failed.getSecurityStatus().initialized, false);
  `,
    ],
    {
      env: {
        ...process.env,
        DBUS_SESSION_BUS_ADDRESS: 'unix:path=/nonexistent-taobao-test-bus',
      },
      timeout: 10000,
      encoding: 'utf8',
    },
  );
  assert.equal(unavailable.status, 0, unavailable.stderr);
}

function testClosedStdio() {
  const closedStdio = spawnSync(
    process.execPath,
    [
      '-e',
      `
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    const {MyAddon} = require(${JSON.stringify(addonPath)});
    fs.closeSync(0); fs.closeSync(1);
    assert.equal(new MyAddon().initializeCrypto(), true);
  `,
    ],
    { env: process.env, timeout: 10000, encoding: 'utf8' },
  );
  assert.equal(closedStdio.status, 0, closedStdio.stderr);
}

function testHelperFailure() {
  // A helper failure must leave the Node/Electron process alive and surface an
  // error. Use a private addon copy; do not modify the real build or SDK.
  const isolated = fs.mkdtempSync(path.join(os.tmpdir(), 'taobao-addon-failure-'));
  try {
    fs.copyFileSync(addonPath, path.join(isolated, 'my_addon.node'));
    const Broken = require(path.join(isolated, 'my_addon.node')).MyAddon;
    assert.throws(() => new Broken().initializeCrypto(), /cannot start/);
    fs.mkdirSync(path.join(isolated, 'bin'));
    fs.writeFileSync(path.join(isolated, 'bin/security-core'), '#!/bin/sh\nexit 77\n', {
      mode: 0o700,
    });
    assert.throws(() => new Broken().initializeCrypto(), /core failed|IPC failed|cannot send/);
  } finally {
    fs.rmSync(isolated, { recursive: true, force: true });
  }
}

async function main() {
  assert.equal(fs.readFileSync(addonPath).subarray(0, 4).toString(), '\x7fELF');

  const native = new MyAddon(`offline-test-${process.pid}`);
  assert.equal(native.getCapabilities().securityFactors, false);
  assert.equal(native.getSecurityStatus().initialized, false);
  assert.equal(native.initializeCrypto(), true);

  testPlatform(native);
  const roundTrips = testEncryption(native);
  testSignaturesAndValidation(native);

  const wrapper = await loadWrapper();
  await testSecurityFactors(native, wrapper);
  testStorage();
  testUnavailableService();
  testClosedStdio();
  testHelperFailure();

  console.log(
    JSON.stringify({
      runtime: process.versions.electron
        ? `Electron ${process.versions.electron}`
        : `Node ${process.version}`,
      napi: process.versions.napi,
      roundTrips,
      urlSignMethods: 3,
      storage: 'passed',
      securityFactors: 'passed',
      serverAcceptance: 'unverified',
    }),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
