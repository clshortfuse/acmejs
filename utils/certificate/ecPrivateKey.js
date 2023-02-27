import { derFromPEM, pemFromDER } from './format.js';

// https://datatracker.ietf.org/doc/html/rfc5915
const EC_PRIVATE_KEY_HEADER = '-----BEGIN EC PRIVATE KEY-----';
const EC_PRIVATE_KEY_FOOTER = '-----END EC PRIVATE KEY-----';

/**
 * @param {string|Uint8Array} ecPrivateKey
 * @return {Uint8Array}
 */
export function derFromECPrivateKey(ecPrivateKey) {
  if (typeof ecPrivateKey !== 'string') return ecPrivateKey;
  return derFromPEM(ecPrivateKey, EC_PRIVATE_KEY_HEADER, EC_PRIVATE_KEY_FOOTER);
}

/**
 * @param {string|Uint8Array} ecPrivateKey
 * @return {string}
 */
export function pemFromECPrivateKey(ecPrivateKey) {
  return pemFromDER(derFromECPrivateKey(ecPrivateKey), EC_PRIVATE_KEY_HEADER, EC_PRIVATE_KEY_FOOTER);
}
