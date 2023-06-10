// https://www.rfc-editor.org/rfc/rfc7518

import { cleanBase64UrlString, decodeBase64AsArray, encodeBase64UrlAsString } from '../utils/base64.js';

/**
 * @param {Pick<ECPublicKey,'crv'>&Record<keyof Omit<ECPublicKey,'kty'|'crv'>, string|Uint8Array|BufferSource>&Partial<Record<keyof ECPrivateKeyFields, string|Uint8Array|BufferSource>>} options
 * @return {ECKey & Pick<JWK, 'key_ops'>}
 */
export function createECKey({ crv, x, y, d }) {
  if (!d) {
    return {
      kty: 'EC',
      crv,
      x: typeof x === 'string' ? cleanBase64UrlString(x) : encodeBase64UrlAsString(x),
      y: typeof y === 'string' ? cleanBase64UrlString(y) : encodeBase64UrlAsString(y),
    };
  }

  return {
    kty: 'EC',
    crv,
    x: typeof x === 'string' ? cleanBase64UrlString(x) : encodeBase64UrlAsString(x),
    y: typeof y === 'string' ? cleanBase64UrlString(y) : encodeBase64UrlAsString(y),
    d: typeof d === 'string' ? cleanBase64UrlString(d) : encodeBase64UrlAsString(d),
  };
}

/**
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {RSAKey & Pick<JWK, 'key_ops'>}
 */
export function createRSAKey({ n, e, d, p, q, dp, dq, qi, oth }) {
  if (!d) {
    return {
      kty: 'RSA',
      n: typeof n === 'string' ? cleanBase64UrlString(n) : encodeBase64UrlAsString(n),
      e: typeof e === 'string' ? cleanBase64UrlString(e) : encodeBase64UrlAsString(e),
    };
  }
  /** @type {RSAPrivateKey} */
  const jwk = {
    kty: 'RSA',
    n: typeof n === 'string' ? cleanBase64UrlString(n) : encodeBase64UrlAsString(n),
    e: typeof e === 'string' ? cleanBase64UrlString(e) : encodeBase64UrlAsString(e),
    d: typeof d === 'string' ? cleanBase64UrlString(d) : encodeBase64UrlAsString(d),
  };
  if (p) jwk.p = typeof p === 'string' ? cleanBase64UrlString(p) : encodeBase64UrlAsString(p);
  if (q) jwk.q = typeof q === 'string' ? cleanBase64UrlString(q) : encodeBase64UrlAsString(q);
  if (dp) jwk.dp = typeof dp === 'string' ? cleanBase64UrlString(dp) : encodeBase64UrlAsString(dp);
  if (dq) jwk.dq = typeof dq === 'string' ? cleanBase64UrlString(dq) : encodeBase64UrlAsString(dq);
  if (qi) jwk.qi = typeof qi === 'string' ? cleanBase64UrlString(qi) : encodeBase64UrlAsString(qi);
  if (oth) jwk.oth = oth;
  return jwk;
}

/**
 * @param {Omit<SymmetricKey,'kty'>|Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {SymmetricKey & Pick<JWK, 'key_ops'>}}
 */
export function createSymmetricKey({ k }) {
  return {
    kty: 'oct',
    k: typeof k === 'string' ? cleanBase64UrlString(k) : encodeBase64UrlAsString(k),
  };
}

/**
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.1
 * @see https://w3c.github.io/webcrypto/#jwk-mapping-alg
 * @param {JWK|string} input
 * @param {boolean} [privateKey]
 * @return {JWK['key_ops']}
 */
export function parseKeyOps(input, privateKey) {
  const alg = typeof input === 'string' ? input : input.alg;
  switch (alg) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'ES256':
    case 'ES384':
    case 'ES512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return privateKey ? ['sign'] : ['verify'];
    case 'RSA1_5':
      return privateKey ? ['sign'] : ['verify'];
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      return privateKey ? ['decrypt'] : ['encrypt'];
    default:
  }

  throw new Error('Unknown `alg` value.');
}

/**
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.1
 * @see https://w3c.github.io/webcrypto/#jwk-mapping-alg
 * @param {JWK|string|Algorithm} input
 * @return {Parameters<SubtleCrypto['sign']>[0]|Parameters<SubtleCrypto['importKey']>[2]}
 */
export function parseAlgorithmIdentifier(input) {
  let keySize = 2048;
  /** @type {string} */
  let alg;
  /** @type {string} */
  let n;
  if (typeof input === 'string') {
    alg = input;
  } else if ('alg' in input) {
    ({ alg, n } = input);
  } else {
    return /** @type {Algorithm} */ (input);
  }

  if (alg.startsWith('PS') && n) {
    keySize = decodeBase64AsArray(n).length * 8;
  }
  switch (alg) {
    case 'HS256': return { name: 'HMAC', hash: { name: 'SHA-256' } };
    case 'HS384': return { name: 'HMAC', hash: { name: 'SHA-384' } };
    case 'HS512': return { name: 'HMAC', hash: { name: 'SHA-512' } };
    case 'RS256': return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    case 'RS384': return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } };
    case 'RS512': return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } };
    case 'ES256': return { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } };
    case 'ES384': return { name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-384' } };
    case 'ES512': return { name: 'ECDSA', namedCurve: 'P-521', hash: { name: 'SHA-512' } };
    case 'PS256': return { name: 'RSA-PSS', saltLength: Math.ceil((keySize - 1) / 8) - (256 / 8) - 2, hash: { name: 'SHA-256' } };
    case 'PS384': return { name: 'RSA-PSS', saltLength: Math.ceil((keySize - 1) / 8) - (384 / 8) - 2, hash: { name: 'SHA-384' } };
    case 'PS512': return { name: 'RSA-PSS', saltLength: Math.ceil((keySize - 1) / 8) - (512 / 8) - 2, hash: { name: 'SHA-512' } };
    case 'RSA1_5': return { name: 'RSA-OAEP', hash: { name: 'SHA-1' } };
    case 'RSA-OAEP': return { name: 'RSA-OAEP', hash: { name: 'SHA-1' } };
    case 'RSA-OAEP-256': return { name: 'RSA-OAEP', hash: { name: 'SHA-256' } };
    case 'RSA-OAEP-384': return { name: 'RSA-OAEP', hash: { name: 'SHA-384' } };
    case 'RSA-OAEP-512': return { name: 'RSA-OAEP', hash: { name: 'SHA-512' } };
    default:
  }

  throw new Error('Unknown `alg` value.');
}

// SIGNING

/**
 * @param {Record<keyof Omit<ECPublicKey,'kty'|'crv'>, string|Uint8Array|BufferSource>&Partial<Record<keyof ECPrivateKeyFields, string|Uint8Array|BufferSource>>} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createES256JWK(options) {
  return {
    alg: 'ES256',
    ...createECKey({ ...options, crv: 'P-256' }),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Record<keyof Omit<ECPublicKey,'kty'|'crv'>, string|Uint8Array|BufferSource>&Partial<Record<keyof ECPrivateKeyFields, string|Uint8Array|BufferSource>>} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createES384JWK(options) {
  return {
    alg: 'ES384',
    ...createECKey({ ...options, crv: 'P-384' }),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Record<keyof Omit<ECPublicKey,'kty'|'crv'>, string|Uint8Array|BufferSource>&Partial<Record<keyof ECPrivateKeyFields, string|Uint8Array|BufferSource>>} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createES512JWK(options) {
  return {
    alg: 'ES512',
    ...createECKey({ ...options, crv: 'P-521' }),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createHS256JWK(options) {
  return {
    alg: 'HS256',
    ...createSymmetricKey(options),
    key_ops: ['sign', 'verify'],
  };
}

/**
 * @param {Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createHS384JWK(options) {
  return {
    alg: 'HS384',
    ...createSymmetricKey(options),
    key_ops: ['sign', 'verify'],
  };
}

/**
 * @param {Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createHS512JWK(options) {
  return {
    alg: 'HS512',
    ...createSymmetricKey(options),
    key_ops: ['sign', 'verify'],
  };
}

/**
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createRS256JWK(options) {
  return {
    alg: 'RS256',
    ...createRSAKey(options),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createRS384JWK(options) {
  return {
    alg: 'RS384',
    ...createRSAKey(options),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createRS512JWK(options) {
  return {
    alg: 'RS512',
    ...createRSAKey(options),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createPS256JWK(options) {
  return {
    alg: 'PS256',
    ...createRSAKey(options),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createPS384JWK(options) {
  return {
    alg: 'PS384',
    ...createRSAKey(options),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

/**
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createPS512JWK(options) {
  return {
    alg: 'PS512',
    ...createRSAKey(options),
    key_ops: [options.d ? 'verify' : 'sign'],
  };
}

// ENCRYPTION

/**
 * RSAES-PKCS1-v1_5
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createRSAJWK(options) {
  return {
    alg: 'RSA1_5',
    ...createRSAKey(options),
    key_ops: [options.d ? 'encrypt' : 'decrypt'],
  };
}

/**
 * RSAES OAEP using default parameters
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createRSAOAEPJWK(options) {
  return {
    alg: 'RSA-OAEP',
    ...createRSAKey(options),
    key_ops: ['encrypt', 'decrypt'],
  };
}

/**
 * RSAES OAEP using SHA-256 and MGF1 with SHA-256
 * @param {Pick<RSAPrivateKey,'oth'>&(Omit<RSAPrivateKey,'kty'>|Record<keyof Omit<RSAPrivateKey,'kty'|'oth'>, string|Uint8Array|BufferSource>)} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createRSAOAEP256JWK(options) {
  return {
    alg: 'RSA-OAEP-256',
    ...createRSAKey(options),
    key_ops: ['encrypt', 'decrypt'],
  };
}

/**
 * AES Key Wrap with default initial value using 128-bit key
 * @param {Omit<SymmetricKey,'kty'>|Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createA128KWJWK(options) {
  return {
    alg: 'A128KW',
    ...createSymmetricKey(options),
    key_ops: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  };
}

/**
 * AES Key Wrap with default initial value using 192-bit key
 * @param {Omit<SymmetricKey,'kty'>|Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createA192KWJWK(options) {
  return {
    alg: 'A192KW',
    ...createSymmetricKey(options),
    key_ops: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  };
}

/**
 * AES Key Wrap with default initial value using 192-bit key
 * @param {Omit<SymmetricKey,'kty'>|Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createA256KWJWK(options) {
  return {
    alg: 'A256KW',
    ...createSymmetricKey(options),
    key_ops: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  };
}

/**
 * Direct use of a shared symmetric key as the CEK
 * @param {Omit<SymmetricKey,'kty'>|Record<keyof Omit<SymmetricKey,'kty'>, string|Uint8Array|BufferSource>} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createSymmetricJWK(options) {
  return {
    alg: 'dir',
    ...createSymmetricKey(options),
    key_ops: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  };
}

/**
 * Elliptic Curve Diffie-Hellman Ephemeral Static
 * @param {Pick<ECPublicKey,'crv'>&Record<keyof Omit<ECPublicKey,'kty'|'crv'>, string|Uint8Array|BufferSource>&Partial<Record<keyof ECPrivateKeyFields, string|Uint8Array|BufferSource>>} options
 * @return {JWK & Required<Pick<JWE, 'alg'>>}
 */
export function createECDHESJWK(options) {
  return {
    alg: 'ECDH-ES',
    ...createECKey(options),
    key_ops: options.d ? ['deriveKey', 'deriveBits'] : [],
  };
}

// UTILS

/**
 * @param {JWK} jwk
 * @return {boolean}
 */
export function isSymmetric(jwk) {
  return jwk.kty === 'oct';
}

/**
 * @param {JWK} jwk
 */
export function isPrivate(jwk) {
  switch (jwk.kty) {
    case 'EC':
    case 'RSA':
      return ('d' in jwk);
    default:
      throw new Error('Unknown JWK!');
  }
}

/**
 * @param {JWK} jwk
 * @return {JWK}
 */
export function extractPublicJWK(jwk) {
  switch (jwk.kty) {
    case 'EC': {
      // @ts-ignore Omit via rest
      // eslint-disable-next-line @typescript-eslint/no-unused-vars, camelcase
      const { d, ext, key_ops, alg, ...publicKey } = jwk;
      return publicKey;
    }
    case 'RSA': {
      // @ts-ignore Omit via rest
      // eslint-disable-next-line @typescript-eslint/no-unused-vars, camelcase
      const { d, p, q, dp, dq, qi, oth, ext, key_ops, alg, ...publicKey } = jwk;
      return publicKey;
    }
    case 'oct':
      // Symmetrical!
      return jwk;
    default:
      throw new Error('Unknown JWK!');
  }
}
