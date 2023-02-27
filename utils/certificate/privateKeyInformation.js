import { parseAlgorithmIdentifier } from '../../lib/jwa.js';
import { ASN_OID, decodeDER, encodeAlgorithmIdentifer, encodeInteger, encodeOctetString, encodeSequence } from '../asn1.js';
import { crypto } from '../crypto.js';

import { derFromPEM, pemFromDER } from './format.js';
import { derFromRSAPrivateKey } from './rsaPrivateKey.js';

/** Encryption not currently supported */

/** */
const PKCS8_HEADER = '-----BEGIN PRIVATE KEY-----';
const PKCS8_FOOTER = '-----END PRIVATE KEY-----';

/**
 * @param {string|Uint8Array} pkcs8 PEM or DER format
 * @return {Uint8Array} DER format
 */
export function derFromPrivateKeyInformation(pkcs8) {
  if (typeof pkcs8 !== 'string') return pkcs8;
  return derFromPEM(pkcs8, PKCS8_HEADER, PKCS8_FOOTER);
}

/**
 * @param {string|Uint8Array} pkcs8
 * @return {string}
 */
export function pemFromPrivateKeyInformation(pkcs8) {
  return pemFromDER(derFromPrivateKeyInformation(pkcs8), PKCS8_HEADER, PKCS8_FOOTER);
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * Unwraps PKCS8 Container for internal key (RSA or EC)
 * @param {string|Uint8Array} pkcs8
 * @param {string} [checkOID]
 * @return {Uint8Array} DER
 */
export function privateKeyFromPrivateKeyInformation(pkcs8, checkOID) {
  const der = derFromPrivateKeyInformation(pkcs8);
  const [
    [privateKeyInfoType, [
      [versionType, version],
      algorithmIdentifierTuple,
      privateKeyTuple,
    ]],
  ] = decodeDER(der);
  if (privateKeyInfoType !== 'SEQUENCE') throw new Error('Invalid PKCS8');
  if (versionType !== 'INTEGER') throw new Error('Invalid PKCS8');
  if (version !== 0) throw new Error('Unsupported PKCS8 Version');
  const [algorithmIdentifierType, algorithmIdentifierValues] = algorithmIdentifierTuple;
  if (algorithmIdentifierType !== 'SEQUENCE') throw new Error('Invalid PKCS8');
  const [privateKeyType, privateKey] = privateKeyTuple;
  if (privateKeyType !== 'OCTET_STRING') throw new Error('Invalid PKCS8');
  if (checkOID) {
    for (const [type, value] of algorithmIdentifierValues) {
      if (type === 'OBJECT_IDENTIFIER' && value === checkOID) {
        return privateKey;
      }
    }
    return null; // Not an error, just doesn't match
  }

  return privateKey;
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * @param {string|Uint8Array} pkcs1
 * @return {Uint8Array} DER
 */
export function privateKeyInformationFromRSAPrivateKey(pkcs1) {
  const der = derFromRSAPrivateKey(pkcs1);

  const privateKeyInfo = encodeSequence(
    encodeInteger(0), // Version

    encodeAlgorithmIdentifer(ASN_OID.rsaEncryption), // PrivateKeyAlgorithm

    encodeOctetString(der), // PrivateKey
  );
  return Uint8Array.from(privateKeyInfo);
}

/**
 * Returns the private key from PKCS8 if it is an EC private key
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * @param {string|Uint8Array} pkcs8
 * @return {Uint8Array}
 */
export function ecPrivateKeyFromPrivateKeyInformation(pkcs8) {
  const privateKey = privateKeyFromPrivateKeyInformation(pkcs8, ASN_OID.ecPublicKey);
  if (!privateKey) {
    throw new Error('NOT AN EC PRIVATE KEY');
  }
  return privateKey;
}

/**
 * Returns the private key from PKCS8 if it is an RSA private key
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * @param {string|Uint8Array} pkcs8
 * @return {Uint8Array}
 */
export function rsaPrivateKeyFromPrivateKeyInformation(pkcs8) {
  const privateKey = privateKeyFromPrivateKeyInformation(pkcs8, ASN_OID.rsaEncryption);
  if (!privateKey) {
    throw new Error('NOT RSA PRIVATE KEY');
  }
  return privateKey;
}

/**
 * @param {JWK} jwk
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<Uint8Array>} DER
 */
export async function privateKeyInformationFromJWK(jwk, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    parseAlgorithmIdentifier(algorithmIdentifier),
    true,
    ['sign'],
  );

  return new Uint8Array(await crypto.subtle.exportKey('pkcs8', key));
}

/**
 * @param {string|Uint8Array} privateKeyInformation PKCS8 in DER Format
 * @param {Parameters<SubtleCrypto['importKey']>[2]|JWK['alg']} algorithmIdentifier
 * @return {Promise<JWK>}
 */
export async function jwkFromPrivateKeyInformation(privateKeyInformation, algorithmIdentifier) {
  const key = await crypto.subtle.importKey(
    'pkcs8',
    derFromPrivateKeyInformation(privateKeyInformation),
    parseAlgorithmIdentifier(algorithmIdentifier),
    true,
    ['sign'],
  );

  const jwk = /** @type {JWK} */ (await crypto.subtle.exportKey('jwk', key));
  return jwk;
}

/**
 * @param {JWK} jwk
 * @param {Parameters<SubtleCrypto['importKey']>[2]} algorithmIdentifier
 * @return {Promise<Uint8Array>}
 */
export async function rsaPrivateKeyFromJWK(jwk, algorithmIdentifier) {
  const pkcs8 = await privateKeyInformationFromJWK(jwk, algorithmIdentifier);
  return rsaPrivateKeyFromPrivateKeyInformation(pkcs8);
}

/**
 * @param {string|Uint8Array} rsaPrivateKey rsaPrivateKey in DER Format
 * @param {Parameters<SubtleCrypto['importKey']>[2]|JWK['alg']} algorithmIdentifier
 * @return {Promise<JWK>}
 */
export async function jwkFromRSAPrivateKey(rsaPrivateKey, algorithmIdentifier) {
  const pkcs1 = privateKeyInformationFromRSAPrivateKey(rsaPrivateKey);
  return await jwkFromPrivateKeyInformation(pkcs1, algorithmIdentifier);
}

// export function privateKeyInformationFromEcPrivateKey
// export function ecPrivateKeyFromPrivateKeyInformation
// export function ecPrivateKeyFromJWK
// export function jwkFromECPrivateKey

export const derFromPKCS8 = derFromPrivateKeyInformation;
export const pemFromPKCS8 = pemFromPrivateKeyInformation;

export const privateKeyInformationFromPKCS1 = privateKeyInformationFromRSAPrivateKey;
export const pkcs8FromRSAPrivateKey = privateKeyInformationFromRSAPrivateKey;
export const pkcs8FromPKCS1 = privateKeyInformationFromRSAPrivateKey;

export const rsaPrivateKeyFromPKCS8 = rsaPrivateKeyFromPrivateKeyInformation;
export const pkcs1FromPKCS8 = rsaPrivateKeyFromPrivateKeyInformation;

export const ecPrivateKeyFromPKCS8 = ecPrivateKeyFromPrivateKeyInformation;

export const pkcs8FromJWK = privateKeyInformationFromJWK;
export const jwkFromPKCS8 = jwkFromPrivateKeyInformation;

export const pkcs1FromJWK = rsaPrivateKeyFromJWK;
export const jwkFromPKCS1 = jwkFromRSAPrivateKey;
