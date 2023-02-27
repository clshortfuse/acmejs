import { encodeBase64UrlAsString } from '../utils/base64.js';
import { digest } from '../utils/crypto.js';

/**
 * @param {Object} object
 * @return {Promise<BASE64URL<any>>}
 */
export async function thumbprintObject(object) {
  const signingInput = JSON.stringify(object);
  const result = await digest('SHA-256', signingInput);
  return encodeBase64UrlAsString(result);
}

/**
 * @param {JWK} jwk
 * @return {Promise<BASE64URL<any>>}
 */
export async function thumbprintEC(jwk) {
  const { crv, kty, x, y } = jwk;
  return await thumbprintObject({ crv, kty, x, y });
}

/**
 * @param {JWK} jwk
 * @return {Promise<BASE64URL<any>>}
 */
export async function thumbprintRSA(jwk) {
  const { e, kty, n } = jwk;
  return await thumbprintObject({ e, kty, n });
}

/**
 * @param {JWK} jwk
 * @return {Promise<BASE64URL<any>>}
 */
export async function thumbprintSymmetrical(jwk) {
  const { k, kty } = jwk;
  return await thumbprintObject({ k, kty });
}

/**
 * @param {JWK} jwk
 * @return {Promise<BASE64URL<any>>}
 */
export async function thumbprintJWK(jwk) {
  switch (jwk.kty) {
    case 'RSA': return await thumbprintRSA(jwk);
    case 'EC': return await thumbprintEC(jwk);
    case 'oct': return await thumbprintSymmetrical(jwk);
    default: throw new Error('Unknown key type');
  }
}
