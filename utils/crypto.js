/* eslint-disable no-bitwise */
/** @typedef {CryptoKey} CryptoUtilsExport */

import { encodeBase64AsString } from './base64.js';
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
    algorithmIdentifier,
    false,
    jwk.key_ops ?? ['sign', 'verify'],
  );
}

/**
 * @param {JWK} jwk
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<string>}
 */
export async function pkcs8FromJWK(jwk, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    algorithmIdentifier,
    true,
    ['sign'],
  );

  const pkcs8 = (await crypto.subtle.exportKey('pkcs8', key));
  return encodeBase64AsString(pkcs8);
}

/**
 * @param {JWK} jwk
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<string>}
 */
export async function pkcs1FromJWK(jwk, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    algorithmIdentifier,
    true,
    ['sign'],
  );

  const pkcs8 = (await crypto.subtle.exportKey('pkcs8', key));

  return encodeBase64AsString(pkcs1);
}

/**
 * @param {JWK} jwk
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<string>}
 */
export async function spkiFromJWK(jwk, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    algorithmIdentifier,
    true,
    ['verify'],
  );

  const spki = (await crypto.subtle.exportKey('spki', key));
  return encodeBase64AsString(spki);
}

/**
 * @param {Uint8Array} pkcs8 PKCS8 in DER Format
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<JWK>}
 */
export async function jwkFromPKCS8(pkcs8, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    algorithmIdentifier,
    true,
    ['sign'],
  );

  const jwk = /** @type {JWK} */ (await crypto.subtle.exportKey('jwk', key));
  return jwk;
}

/**
 * @param {Uint8Array} spki
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<JWK>}
 */
export async function jwkFromSPKI(spki, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'spki',
    spki,
    algorithmIdentifier,
    true,
    ['verify'],
  );

  const jwk = /** @type {JWK} */ (await crypto.subtle.exportKey('jwk', key));
  return jwk;
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

