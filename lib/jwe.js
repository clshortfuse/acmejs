import { decodeBase64UrlAsArray, decodeBase64UrlAsString, encodeBase64UrlAsString } from '../utils/base64.js';
import { octetFromUtf8 } from '../utils/utf8.js';

import { encodeProtectedHeader } from './jose.js';

/**
 * @typedef {Object} CreateEncryptionRecipientOptions
 * @prop {JWEUnprotectedHeader} [header] unprotected header
 * @prop {JWEProtectedHeader|string|ArrayBuffer|Uint8Array} [protected] protected header
 * @prop {string} [encodedProtected]
 * @prop {JWSPayload} [payload]
 * @prop {string} [encodedPayload]
 * @prop {JWK} [jwk] omit if unsecured
 */

/**
 * https://datatracker.ietf.org/doc/html/rfc7515#section-5.1
 * @param {CreateEncryptionRecipientOptions} options
 * @return {Promise<JWERecipient>}
 */
export async function createEncryptionRecipient({
  header,
  protected: protectedVar,
  encodedProtected = (protectedVar == null ? null : encodeProtectedHeader(protectedVar)),
  payload,
  encodedPayload = encodePayload(payload),
  jwk,
}) {
  const keyManagementMode;

  /** @type {JWSSigningInput} */
  const signingInput = `${encodedProtected}.${encodedPayload}`;

  const decodedProtected = decodeProtectedHeader(protectedVar ?? encodedProtected);
  const joseHeader = {
    ...header,
    ...decodedProtected,
  };

  let encodedSignature;
  if (joseHeader.alg === 'none') {
    if (jwk != null) throw new Error('Invalid algorithm.');
    encodedSignature = '';
  } else {
    if (jwk == null) throw new Error('Missing signing key.');
    /** @type {JWSSignature} */
    const jwsSignature = await KeyStore.default.sign(jwk, signingInput);
    encodedSignature = encodeBase64UrlAsString(jwsSignature);
  }

  return {
    signature: encodedSignature,
    ...(header ? { header } : null),
    ...(encodedProtected ? { protected: encodedProtected } : null),
  };
}

/**
 * @param {string|BufferSource} plaintext
 * @return {Uint8Array}
 */
export function plaintextAsUint8Array(plaintext) {
  if (typeof plaintext === 'string') return Uint8Array.from(octetFromUtf8(plaintext));
  if (plaintext instanceof Uint8Array) return plaintext;
  if (plaintext instanceof ArrayBuffer) return new Uint8Array(plaintext);
  return new Uint8Array(plaintext.buffer);
}

/**
 * @param {string|JWECompactSerialization} jwe
 * @return {JWEFlattened}
 */
export function uncompactJWE(jwe) {
  const [protectedVar, encryptedKey, iv, ciphertext, tag] = jwe.split('.');
  /** @type {JWEFlattened} */
  const flattened = {
    protected: protectedVar,
    ciphertext,
  };
  if (iv) flattened.iv = iv;
  if (encryptedKey) flattened.encrypted_key = encryptedKey;
  if (tag) flattened.tag = tag;
  return flattened;
}

/**
 * @param {Object} options
 * @param {JWEProtectedHeader|string|ArrayBuffer|Uint8Array} [options.protected]
 * @param {string|BufferSource} options.plaintext
 * @param {JWK} options.jwk
 * @return {Promise<JWSCompactSerialization>}
 */
export async function encryptCompact({ protected: protectedVar, plaintext, jwk }) {
  const encodedProtected = encodeProtectedHeader(protectedVar);
  const plainTextArray = plaintextAsUint8Array(plaintext);
  const ciphertext = await createSignature({ encodedProtected, encodedPayload, jwk });
  return `${encodedProtected}.${encodedPayload}.${signature}`;
}
