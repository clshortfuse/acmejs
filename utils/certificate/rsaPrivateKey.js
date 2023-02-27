import { derFromPEM, pemFromDER } from './format.js';

/**
 * Use SPKI instead for RSA Public Keys
 * Public keys in PKCS1 are not supported
 */

/** */
const RSA_PRIVATE_KEY_HEADER = '-----BEGIN RSA PRIVATE KEY-----';
const RSA_PRIVATE_KEY_FOOTER = '-----END RSA PRIVATE KEY-----';

/**
 * @param {string|Uint8Array} rsaPrivateKey
 * @return {Uint8Array}
 */
export function derFromRSAPrivateKey(rsaPrivateKey) {
  if (typeof rsaPrivateKey !== 'string') return rsaPrivateKey;
  return derFromPEM(rsaPrivateKey, RSA_PRIVATE_KEY_HEADER, RSA_PRIVATE_KEY_FOOTER);
}

/**
 * @param {string|Uint8Array} rsaPrivateKey
 * @return {string}
 */
export function pemFromRSAPrivateKey(rsaPrivateKey) {
  return pemFromDER(derFromRSAPrivateKey(rsaPrivateKey), RSA_PRIVATE_KEY_HEADER, RSA_PRIVATE_KEY_FOOTER);
}

export const derFromPKCS1 = derFromRSAPrivateKey;
export const pemFromPKCS1 = pemFromRSAPrivateKey;
