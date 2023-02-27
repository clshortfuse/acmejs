import { parseAlgorithmIdentifier } from '../../lib/jwa.js';
import { encodeBase64AsString } from '../base64.js';
import { crypto } from '../crypto.js';

import { derFromPEM, pemFromDER } from './format.js';

const SPKI_HEADER = '-----BEGIN PUBLIC KEY-----';
const SPKI_FOOTER = '-----END PUBLIC KEY-----';

/**
 * @param {string|Uint8Array} spki
 * @return {Uint8Array}
 */
export function derFromPublicKey(spki) {
  if (typeof spki !== 'string') return spki;
  return derFromPEM(spki, SPKI_HEADER, SPKI_FOOTER);
}

/**
 * @param {string|Uint8Array} spki
 * @return {string}
 */
export function pemFromPublicKey(spki) {
  return pemFromDER(derFromPublicKey(spki), SPKI_HEADER, SPKI_FOOTER);
}

/**
 * @param {JWK} jwk
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<string>}
 */
export async function publicKeyFromJWK(jwk, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    parseAlgorithmIdentifier(algorithmIdentifier),
    true,
    ['verify'],
  );

  const spki = (await crypto.subtle.exportKey('spki', key));
  return encodeBase64AsString(spki);
}

/**
 * @param {Uint8Array} spki
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<JWK>}
 */
export async function jwkFromPublicKey(spki, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'spki',
    spki,
    parseAlgorithmIdentifier(algorithmIdentifier),
    true,
    ['verify'],
  );

  const jwk = /** @type {JWK} */ (await crypto.subtle.exportKey('jwk', key));
  return jwk;
}

export const derFromSPKI = derFromPublicKey;
export const pemFromSPKI = pemFromPublicKey;
export const jwkFromSPKI = jwkFromPublicKey;
export const spkiFromJWK = publicKeyFromJWK;
