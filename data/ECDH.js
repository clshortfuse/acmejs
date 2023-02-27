// https://www.rfc-editor.org/rfc/rfc8037.html

/**
 * When the JWK "kty" member value is "oct" (octet sequence), the member
 * "k" (see Section 6.4.1) is used to represent a symmetric key (or
 * another key whose value is a single octet sequence).  An "alg" member
 * SHOULD also be present to identify the algorithm intended to be used
 * with the key, unless the application uses another means or convention
 * to determine the algorithm used.
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.4
 * @typedef {SymmetricKeyFields} SymmetricKey
 */

/**
 * @typedef {Object} JWAHeaderEdDSA
 * @prop {'EdDSA'} alg
 * @prop {EphemeralPublicKeyEdwardsCurve} epk Ephemeral Public Key
 * @prop {string} [apu] Agreement PartyUInfo
 * @prop {string} [apv] Agreement PartyVInfo
 */

/**
 * Digital Signature with ECDSA
 * @typedef {Object} JWAHeaderECDSA
 * @prop {`ES${'256'|'384'|'512'}`} alg
 * @prop {EphemeralPublicKeyEllipticCurveP} epk Ephemeral Public Key
 * @prop {string} [apu] Agreement PartyUInfo
 * @prop {string} [apv] Agreement PartyVInfo
 */

/**
 * @typedef {Object} JWAHeaderECDH
 * @prop {'ECDH'|'ECDH-ES'|`ECDH-ES+A${'128'|'192'|'256'}KW`} alg
 * @prop {EphemeralPublicKeyEllipticCurve} epk Ephemeral Public Key
 * @prop {string} [apu] Agreement PartyUInfo
 * @prop {string} [apv] Agreement PartyVInfo
 */

/**
 * @typedef {Object} JWAHeaderAESGCM
 * @prop {`A${'128'|'192'|'256'}GCMKW`} alg
 * @prop {string} iv Initialization Vector
 * @prop {string} tag Authentication Tag
 */

/**
 * @typedef {Object} JWAHeaderPBES2
 * @prop {`PBES2-HS${'256+A128'|'384+A192'|'512+A256'}KW`} alg
 * @prop {string} p2s PBES2 Salt Input
 * @prop {number} p2c PBES2 Count
 */

/**
 * @typedef {Object} JWAHeaderOther
 * @prop {'RSA1_5'|`RSA-OAEP${''|'-256'}`|`A${'128'|'192'|'256'}KW`|'dir'} alg
 */

/** @typedef {JWAHeaderSignatureOrMac|JWAHeaderECDH|JWAHeaderAESGCM|JWAHeaderPBES2|JWAHeaderEdDSA|JWAHeaderOther} JWAHeader */

/**
 * @template {JWAHeader} [T=JWAHeader]
 * @typedef {JWSHeaderBase & Pick<T,'alg'> & ({jwk:Omit<T,'alg'>} | {kid:string})} JWSHeader
 */

/**
 * @template {Object} [T={}]
 * @typedef {JWSFlattened & JWSSignature<JWAHeader>} ACMEJWS<T>
 */

/**
 * @typedef {Object} EphemeralPublicKeyEdwardsCurve
 * @prop {'OKP'} kty Key type
 * @prop {`Ed${'25519'|'448'}`} crv signature algorithm
 * @prop {string} x x coordinate for the Elliptic Curve point.
 * @prop {string} [y] y coordinate for the Elliptic Curve point.
 */
