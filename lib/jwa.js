import { decodeBase64AsArray, encodeBase64UrlAsString } from '../utils/base64.js';

/**
 * @param {Pick<ECPublicKey,'crv'>&Record<keyof Omit<ECPublicKey,'kty'|'crv'>, string|Uint8Array|BufferSource>&Partial<Record<keyof ECPrivateKeyFields, string|Uint8Array|BufferSource>>} options
 * @return {ECKey & Pick<JWK, 'key_ops'>}
 */
export function createECKey({ crv, x, y, d }) {
  if (!d) {
    return {
      kty: 'EC',
      crv,
      x: typeof x === 'string' ? x : encodeBase64UrlAsString(x),
      y: typeof y === 'string' ? y : encodeBase64UrlAsString(y),
      key_ops: ['verify'],
    };
  }

  return {
    kty: 'EC',
    crv,
    x: typeof x === 'string' ? x : encodeBase64UrlAsString(x),
    y: typeof y === 'string' ? y : encodeBase64UrlAsString(y),
    d: typeof d === 'string' ? d : encodeBase64UrlAsString(d),
    key_ops: ['sign'],
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
      n: typeof n === 'string' ? n : encodeBase64UrlAsString(n),
      e: typeof e === 'string' ? e : encodeBase64UrlAsString(e),
      key_ops: ['verify'],
    };
  }
  /** @type {RSAPrivateKey} */
  const jwk = {
    kty: 'RSA',
    n: typeof n === 'string' ? n : encodeBase64UrlAsString(n),
    e: typeof e === 'string' ? e : encodeBase64UrlAsString(e),
    d: typeof d === 'string' ? d : encodeBase64UrlAsString(d),
    key_ops: ['sign'],
  };
  if (p) jwk.p = typeof p === 'string' ? p : encodeBase64UrlAsString(p);
  if (q) jwk.q = typeof q === 'string' ? q : encodeBase64UrlAsString(q);
  if (dp) jwk.dp = typeof dp === 'string' ? dp : encodeBase64UrlAsString(dp);
  if (dq) jwk.dq = typeof dq === 'string' ? dq : encodeBase64UrlAsString(dq);
  if (qi) jwk.qi = typeof qi === 'string' ? qi : encodeBase64UrlAsString(qi);
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
    k: typeof k === 'string' ? k : encodeBase64UrlAsString(k),
    key_ops: ['sign', 'verify'],
  };
}

/**
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-3.1
 * @see https://w3c.github.io/webcrypto/#jwk-mapping-alg
 * @param {JWK} jwk
 * @return {Parameters<SubtleCrypto['sign']>[0]|Parameters<SubtleCrypto['importKey']>[2]}
 */
export function parseAlgorithmIdentifier(jwk) {
  let keySize;
  if (jwk.alg.startsWith('PS')) {
    keySize = jwk.n ? decodeBase64AsArray(jwk.n).length * 8 : 2048;
  }
  switch (jwk.alg) {
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
    default:
  }
  throw new Error('Unknown `alg` value.');
}

/**
 * @param {Record<keyof Omit<ECPublicKey,'kty'|'crv'>, string|Uint8Array|BufferSource>&Partial<Record<keyof ECPrivateKeyFields, string|Uint8Array|BufferSource>>} options
 * @return {JWK & Required<Pick<JWS, 'alg'>>}
 */
export function createES256JWK(options) {
  return {
    alg: 'ES256',
    ...createECKey({ ...options, crv: 'P-256' }),
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
  };
}

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
