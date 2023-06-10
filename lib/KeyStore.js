/** @typedef {JWK & Required<Pick<JWK, 'alg'>>} JWKWithAlgorithm */

import { encrypt, importJWK, sign, verify } from '../utils/crypto.js';

import { extractPublicJWK, isPrivate, isSymmetric, parseAlgorithmIdentifier, parseKeyOps } from './jwa.js';

/**
 * @typedef {Object} KeyCacheItem
 * @prop {CryptoKey} privateKey
 * @prop {CryptoKey} publicKey
 * @prop {JWK} jwk
 * @prop {AlgorithmIdentifier} algorithmIdentifier
 */

export default class KeyStore {
  /** @typedef {WeakMap<JWK, KeyCacheItem>} */
  #cacheByJWK = new WeakMap();

  /** @typedef {Map<string, KeyCacheItem>} */
  #cacheByKeyID = new Map();

  static default = new KeyStore();

  /**
   * @param {JWK} jwk
   * @param {AlgorithmIdentifier} [algorithmIdentifier]
   * @return {Promise<KeyCacheItem>}
   */
  async importJWK(jwk, algorithmIdentifier) {
    const parsedAlgorithmIdentifier = algorithmIdentifier ?? parseAlgorithmIdentifier(jwk);
    let publicKey;
    let privateKey;
    if (isSymmetric(jwk)) {
      const key = await importJWK(jwk, parsedAlgorithmIdentifier);
      publicKey = key;
      privateKey = key;
    } else if (isPrivate(jwk)) {
      privateKey = await importJWK({ ...jwk, key_ops: parseKeyOps(jwk, true) }, parsedAlgorithmIdentifier);
      publicKey = await importJWK({ ...extractPublicJWK(jwk), key_ops: parseKeyOps(jwk) }, parsedAlgorithmIdentifier);
    } else {
      publicKey = await importJWK({ ...jwk, key_ops: parseKeyOps(jwk) }, parsedAlgorithmIdentifier);
    }

    const cacheItem = {
      jwk,
      algorithmIdentifier: parsedAlgorithmIdentifier,
      publicKey,
      privateKey,
    };
    this.#cacheByJWK.set(jwk, cacheItem);
    if (jwk.kid) {
      this.#cacheByKeyID.set(jwk.kid, cacheItem);
    }
    return cacheItem;
  }

  /**
   * @param {JWK} jwk
   * @param {boolean} [autoImport=false]
   * @return {Promise<KeyCacheItem>}
   */
  async retrieveKey(jwk, autoImport) {
    if (jwk.kid && this.#cacheByKeyID.has(jwk.kid)) return this.#cacheByKeyID.get(jwk.kid);
    if (this.#cacheByJWK.has(jwk)) return this.#cacheByJWK.get(jwk);
    if (autoImport) return await this.importJWK(jwk);
    throw new Error('Key not found!');
  }

  /**
   * @param {JWK} jwk
   * @param {string|BufferSource} data
   * @return {Promise<ArrayBuffer>}
   */
  async sign(jwk, data) {
    const cacheItem = await this.retrieveKey(jwk, true);
    return await sign(cacheItem.algorithmIdentifier, cacheItem.privateKey, data);
  }

  /**
   * @param {JWK} jwk
   * @return {boolean}
   */
  static canSign(jwk) {
    return isSymmetric(jwk) || isPrivate(jwk);
  }

  /**
   * @param {JWK} jwk
   * @param {BufferSource} signature
   * @param {BufferSource} data
   * @return {Promise<boolean>}
   */
  async verify(jwk, signature, data) {
    const cacheItem = await this.retrieveKey(jwk, true);
    return await verify(cacheItem.algorithmIdentifier, cacheItem.publicKey, signature, data);
  }

  /**
   * @param {JWK} jwk
   * @param {BufferSource} data
   * @return {Promise<ArrayBuffer>}
   */
  async encrypt(jwk, data) {
    const cacheItem = await this.retrieveKey(jwk, true);
    const encryptJWK = cacheItem.publicKey.usages.includes('encrypt')
      ? cacheItem.publicKey
      : cacheItem.privateKey;
    return await encrypt(cacheItem.algorithmIdentifier, encryptJWK, data);
  }
}
