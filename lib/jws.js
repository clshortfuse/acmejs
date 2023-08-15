import { decodeBase64UrlAsArray, decodeBase64UrlAsString, encodeBase64UrlAsString } from '../utils/base64.js';
import { uint8ArrayFromUtf8 } from '../utils/utf8.js';

import KeyStore from './KeyStore.js';
import { decodeProtectedHeader, encodePayload, encodeProtectedHeader } from './jose.js';

/**
 * @typedef {Object} CreateSignatureOptions
 * @prop {JWSUnprotectedHeader} [header] unprotected header
 * @prop {JWSProtectedHeader|string|ArrayBuffer|Uint8Array} [protected] protected header
 * @prop {string} [encodedProtected]
 * @prop {JWSPayload} [payload]
 * @prop {string} [encodedPayload]
 * @prop {JWK} [jwk] omit if unsecured
 */

/**
 * https://datatracker.ietf.org/doc/html/rfc7515#section-5.1
 * @param {CreateSignatureOptions} options
 * @return {Promise<JWSSignatureObject>}
 */
export async function createSignature({
  header,
  protected: protectedVar,
  encodedProtected = (protectedVar == null ? null : encodeProtectedHeader(protectedVar)),
  payload,
  encodedPayload = encodePayload(payload),
  jwk,
}) {
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
 * @param {Object} options
 * @param {JWSProtectedHeader|string|ArrayBuffer|Uint8Array} [options.protected]
 * @param {JWSPayload} options.payload
 * @param {JWK} options.jwk
 * @return {Promise<JWSCompactSerialization>}
 */
export async function signCompact({ protected: protectedVar, payload, jwk }) {
  const encodedProtected = encodeProtectedHeader(protectedVar);

  const encodedPayload = encodePayload(payload);

  const { signature } = await createSignature({ encodedProtected, encodedPayload, jwk });
  return `${encodedProtected}.${encodedPayload}.${signature}`;
}

/**
 * @param {JWSFlattened} JWS
 * @return {JWSCompactSerialization}
 */
export function compact({ protected: protectedVar, payload, signature }) {
  return `${protectedVar}.${payload}.${signature}`;
}

/**
 * @template {any} T1
 * @template {any} T2
 * @param {Object} options
 * @param {JWSUnprotectedHeader<T1>} [options.header] Unprotected Header
 * @param {JWSProtectedHeader<T2>|string|ArrayBuffer|Uint8Array} [options.protected] Protected Header
 * @param {JWSPayload} [options.payload]
 * @param {string} [options.encodedPayload]
 * @param {JWK} [options.jwk]
 * @param {Exclude<CreateSignatureOptions, 'payload'|'encodedPayload'>[]} [options.signatures]
 * @return {Promise<JWSJSONSerialization>}
 */
export async function signObject({
  header,
  protected: protectedVar,
  payload, encodedPayload = encodePayload(payload),
  jwk,
  signatures,
}) {
  const len = signatures?.length;
  if (!len) {
    /** @type {JWSFlattened} */
    return {
      payload: encodedPayload,
      ...(
        await createSignature({
          header,
          protected: protectedVar,
          encodedPayload,
          jwk,
        })
      ),
    };
  }
  if (len === 1) {
    const [signature] = signatures;
    /** @type {JWSFlattened} */
    return {
      payload: encodedPayload,
      ...(
        await createSignature({
          header: signature.header ?? header,
          protected: signature.protected ?? protectedVar,
          encodedPayload,
          jwk: signature.jwk,
        })
      ),
    };
  }
  /** @type {JWSGeneral} */
  return {
    payload: encodedPayload,
    signatures: await Promise.all(signatures.map((signature) => createSignature({
      header: signature.header ?? header,
      protected: signature.protected ?? protectedVar,
      encodedPayload,
      jwk: signature.jwk,
    }))),
  };
}

/**
 * @param {string|JWSCompactSerialization} jws
 * @return {JWSFlattened}
 */
export function uncompactJWS(jws) {
  const [protectedVar, payload, signature] = jws.split('.');
  return {
    protected: protectedVar,
    payload,
    signature,
  };
}

/**
 * @param {string} encodedPayload
 * @param {JWSSignatureObject} signatureObject
 * @param {JWK} [jwk] omit if unsecured
 * @return {Promise<void>} encoded payload
 */
export async function validateSignature(encodedPayload, signatureObject, jwk) {
  // const signingInput = /** @type {JWSSigningInput} */ (jws.slice(0, jws.lastIndexOf('.')));
  const { header, protected: protectedVar, signature } = signatureObject;
  const signingInput = `${protectedVar}.${encodedPayload}`;
  const decodedProtected = protectedVar ? decodeProtectedHeader(protectedVar) : null;
  const joseHeader = {
    ...header,
    ...decodedProtected,
  };
  if (joseHeader.alg === 'none') {
    if (jwk == null && !signature) return;
    throw new Error('Invalid signature.');
  }
  if (!signature) throw new Error('Invalid signature.');
  if (jwk == null) throw new Error('Invalid signature.');
  try {
    const verified = await KeyStore.default.verify(
      jwk,
      decodeBase64UrlAsArray(signature),
      uint8ArrayFromUtf8(signingInput),
    );
    if (verified) return;
  } catch (e) { console.error(e); }
  throw new Error('Invalid signature.');
}

/**
 * @param {JWSFlattened} jws
 * @param {JWK} jwk
 * @return {Promise<string>} encoded payload
 */
export async function validateFlattened(jws, jwk) {
  await validateSignature(jws.payload, jws, jwk);
  return jws.payload;
}

/**
 * @param {JWSCompactSerialization} jws
 * @param {JWK} [jwk] omit if unsecured
 * @return {Promise<string>} encoded payload
 */
export async function validateCompact(jws, jwk) {
  const flattenedJWS = uncompactJWS(jws);
  return await validateFlattened(flattenedJWS, jwk);
}

/**
 * @param {JWSGeneral} jws
 * @param {JWK} [jwk] omit if unsecured
 * @return {Promise<string>} encoded payload
 */
export async function validateGeneral(jws, jwk) {
  const { payload, signatures } = jws;
  const responses = await Promise.allSettled(signatures.map((signature) => validateSignature(payload, signature, jwk)));

  for (const { status } of responses) {
    if (status === 'fulfilled') return payload;
  }
  throw new Error('Invalid signature');
}

/**
 * @param {JWS} jws
 * @param {JWK} [jwk] omit if unsecured
 * @return {Promise<JWSPayload>} decoded payload
 */
export async function validate(jws, jwk) {
  if (typeof jws === 'string') return await validateCompact(jws, jwk);
  if (!('signatures' in jws)) return await validateFlattened(jws, jwk);
  return await validateGeneral(jws, jwk);
}

/**
 * @param {JWS} jws
 * @param {JWK} [jwk] omit if unsecured
 * @return {Promise<string>} decoded payload
 */
export async function decodeString(jws, jwk) {
  const payload = await validate(jws, jwk);
  return decodeBase64UrlAsString(payload);
}

/**
 * @param {JWS} jws
 * @return {string} decoded payload
 */
export function decodeStringUnsafe(jws) {
  const object = (typeof jws === 'string') ? uncompactJWS(jws) : jws;
  return decodeBase64UrlAsString(object.payload);
}

/**
 * @param {JWS} jws
 * @param {JWK} [jwk] omit if unsecured
 * @return {Promise<JWSPayload>} encoded payload
 */
export async function decodeUint8Array(jws, jwk) {
  const payload = await validate(jws, jwk);
  return decodeBase64UrlAsArray(payload);
}

/**
 * @param {JWS} jws
 * @return {Uint8Array} decoded payload
 */
export function decodeUint8ArrayUnsafe(jws) {
  const object = (typeof jws === 'string') ? uncompactJWS(jws) : jws;
  return decodeBase64UrlAsArray(object.payload);
}

/**
 * @param {JWS} jws
 * @param {JWK} [jwk] omit if unsecured
 * @return {Promise<JWSPayload>} encoded payload
 */
export async function decodeJSON(jws, jwk) {
  return JSON.parse(await decodeString(jws, jwk));
}

/**
 * @param {JWS} jws
 * @return {Object} decoded payload
 */
export function decodeJSONUnsafe(jws) {
  return JSON.parse(decodeStringUnsafe(jws));
}
