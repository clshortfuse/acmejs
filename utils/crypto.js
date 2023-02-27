/* eslint-disable no-bitwise */
/** @typedef {CryptoKey} CryptoUtilsExport */

import { parseAlgorithmIdentifier } from '../lib/jwa.js';

import { octetFromUtf8 } from './utf8.js';

/** @type {Crypto} */
// eslint-disable-next-line unicorn/no-await-expression-member
export const crypto = globalThis.crypto ?? (await import(new URL('node:crypto').toString())).webcrypto;

/**
 * @param {JWK} jwk
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<CryptoUtilsExport>}
 */
export async function importJWK(jwk, algorithmIdentifier) {
  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    parseAlgorithmIdentifier(algorithmIdentifier),
    false,
    jwk.key_ops ?? ['sign', 'verify'],
  );
}

/**
 * @param {Parameters<SubtleCrypto['sign']>[0]} algorithmIdentifier
 * @param {CryptoUtilsExport} key
 * @param {string|BufferSource} data
 * @return {Promise<ArrayBuffer>}
 */
export async function sign(algorithmIdentifier, key, data) {
  const binary = typeof data === 'string' ? Uint8Array.from(octetFromUtf8(data)) : data;
  return await crypto.subtle.sign(algorithmIdentifier, key, binary);
}

/**
 * @param {Parameters<SubtleCrypto['verify']>[0]} algorithmIdentifier
 * @param {CryptoUtilsExport} key
 * @param {BufferSource} signature
 * @param {BufferSource} data
 * @return {Promise<boolean>}
 */
export async function verify(algorithmIdentifier, key, signature, data) {
  return await crypto.subtle.verify(algorithmIdentifier, key, signature, data);
}

/**
 * @param {Parameters<SubtleCrypto['encrypt']>[0]} algorithmIdentifier
 * @param {CryptoUtilsExport} key
 * @param {BufferSource} data
 * @return {Promise<ArrayBuffer>}
 */
export async function encrypt(algorithmIdentifier, key, data) {
  return await crypto.subtle.encrypt(algorithmIdentifier, key, data);
}

/**
 * @param {Parameters<SubtleCrypto['decrypt']>[0]} algorithmIdentifier
 * @param {CryptoUtilsExport} key
 * @param {BufferSource} data
 * @return {Promise<ArrayBuffer>}
 */
export async function decrypt(algorithmIdentifier, key, data) {
  return await crypto.subtle.decrypt(algorithmIdentifier, key, data);
}

/**
 * @param {'SHA-1'|'SHA-256'|'SHA-384'|'SHA-512'} algorithm
 * @param {string|BufferSource} data
 * @return {Promise<ArrayBuffer>}
 */
export async function digest(algorithm, data) {
  const binary = typeof data === 'string' ? Uint8Array.from(octetFromUtf8(data)) : data;
  return await crypto.subtle.digest(algorithm, binary);
}
