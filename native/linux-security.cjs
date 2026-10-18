'use strict';

const { EventEmitter } = require('node:events');
const path = require('node:path');
const crypto = require('node:crypto');

const dataDirectory =
  process.env.TAOBAO_INSTALL_DIR || process.env.TAOBAO_HOME || path.join(__dirname, '../build');
const { MyAddon } = require(path.join(dataDirectory, 'native/security-bodyguard/my_addon.node'));

class SecurityBodyguard extends EventEmitter {
  constructor(namespace) {
    super();
    this.addon = new MyAddon(namespace);
    this._initialized = false;
  }

  async initializeSecurity() {
    this._initialized = this.addon.initializeSecurity('');
    this.emit(this._initialized ? 'initialized' : 'initializationFailed');
    return this._initialized;
  }

  initializeCrypto() {
    return this.addon.initializeCrypto();
  }

  cleanupSecurity() {
    this.addon.cleanupSecurity();
    this._initialized = false;
    this.emit('cleanedUp');
  }

  async getSecurityFactors(url) {
    if (typeof url !== 'string') throw new TypeError('url must be a string');
    const parsed = new URL(url);
    const parameters = {
      api: parsed.host + parsed.pathname,
      urlmd5: crypto
        .createHash('md5')
        .update(parsed.pathname + parsed.search)
        .digest('hex'),
      timestamp: Math.floor(Date.now() / 1000).toString(),
      urlInput: url,
    };
    const result = this.addon.getSecurityFactors(JSON.stringify(parameters));
    this.emit(result.success ? 'securityFactorsReceived' : 'securityFactorsFailed', result);
    return result;
  }

  helloWorld(input = '') {
    return this.addon.helloWorld(input);
  }

  testStorage() {
    return this.addon.testStorage();
  }

  storeWrite(key, value, cover = false) {
    return this.addon.storeWrite(key, value, cover);
  }

  storeRead(key) {
    return this.addon.storeRead(key);
  }

  storeDelete(key) {
    return this.addon.storeDelete(key);
  }

  storeDeleteDatabase() {
    return this.addon.storeDeleteDatabase();
  }

  staticEncrypt(method, input, inputBase64 = false, outputBase64 = true) {
    return this.addon.staticEncrypt(method, input, inputBase64, outputBase64);
  }

  staticDecrypt(method, input, inputBase64 = true, outputBase64 = false) {
    return this.addon.staticDecrypt(method, input, inputBase64, outputBase64);
  }

  isInitialized() {
    return this._initialized;
  }

  getCapabilities() {
    return this.addon.getCapabilities();
  }

  getSecurityStatus() {
    return this.addon.getSecurityStatus();
  }

  getLinuxCollectionInfo() {
    return this.addon.getLinuxCollectionInfo();
  }

  getStatus() {
    return {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      initialized: this._initialized,
      hasNativeAddon: true,
      capabilities: this.getCapabilities(),
      security: this.getSecurityStatus(),
    };
  }
}

module.exports = new SecurityBodyguard();
module.exports.SecurityBodyguard = SecurityBodyguard;
