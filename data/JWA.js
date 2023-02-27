// https://datatracker.ietf.org/doc/html/rfc7518

/**
 * @typedef {Object} JWAHeaderSignatureOrMac
 * @prop {'none'|`${'HS'|'RS'|'ES'|'PS'}${'256'|'384'|'512'}`} alg
 */

/**
 * @typedef {Object} ECPublicKeyFields
 * @prop {'EC'} kty
 * @prop {`P-${'256'|'384'|'521'}`} crv curve
 * The "crv" (curve) parameter identifies the cryptographic curve used
 * with the key.
 * @prop {BASE64URL<any>} x x coordinate
 * The "x" (x coordinate) parameter contains the x coordinate for the
 * Elliptic Curve point.  It is represented as the base64url encoding of
 * the octet string representation of the coordinate, as defined in
 * Section 2.3.5 of SEC1 [SEC1].  The length of this octet string MUST
 * be the full size of a coordinate for the curve specified in the "crv"
 * parameter.  For example, if the value of "crv" is "P-521", the octet
 * string must be 66 octets long.
 * @prop {BASE64URL<any>} y y coordinate
 * The "y" (y coordinate) parameter contains the y coordinate for the
 * Elliptic Curve point.  It is represented as the base64url encoding of
 * the octet string representation of the coordinate, as defined in
 * Section 2.3.5 of SEC1 [SEC1].  The length of this octet string MUST
 * be the full size of a coordinate for the curve specified in the "crv"
 * parameter.  For example, if the value of "crv" is "P-521", the octet
 * string must be 66 octets long.
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2
 * @typedef {Object} ECPrivateKeyFields
 * @prop {BASE64URL<any>} d ECC private key
 * The "d" (ECC private key) parameter contains the Elliptic Curve
 * private key value.  It is represented as the base64url encoding of
 * the octet string representation of the private key value, as defined
 * in Section 2.3.7 of SEC1 [SEC1].  The length of this octet string
 * MUST be ceiling(log-base-2(n)/8) octets (where n is the order of the
 * curve).
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1
 * @typedef {ECPublicKeyFields} ECPublicKey
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2
 * @typedef {ECPublicKey & ECPrivateKeyFields} ECPrivateKey
 */

/**
 *  JWKs can represent Elliptic Curve [DSS] keys.  In this case, the
 * "kty" member value is "EC".
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
 * @typedef {ECPublicKey | ECPrivateKey} ECKey
 */

/**
 * @typedef {Object} RSAOtherPrimeInfo
 * @prop {BASE64URLUINT<any>} r a subsequent prime factor
 * @prop {BASE64URLUINT<any>} d CRT exponent of the corresponding prime factor
 * @prop {BASE64URLUINT<any>} t CRT coefficient of the corresponding prime
 * factor
 */

/**
 * In addition to the members used to represent RSA public keys, the
 * following members are used to represent RSA private keys.  The
 * parameter "d" is REQUIRED for RSA private keys.  The others enable
 * optimizations and SHOULD be included by producers of JWKs
 * representing RSA private keys.  If the producer includes any of the
 * other private key parameters, then all of the others MUST be present,
 * with the exception of "oth", which MUST only be present when more
 * than two prime factors were used.
 * @typedef {Object} RSAPrivateKeyFields
 * @prop {BASE64URLUINT<any>} d private exponent value for the RSA private key.
 * @prop {BASE64URLUINT<any>} [p] first prime factor
 * @prop {BASE64URLUINT<any>} [q] second prime factor
 * @prop {BASE64URLUINT<any>} [dp] Chinese Remainder Theorem (CRT) exponent of the
 * first factor
 * @prop {BASE64URLUINT<any>} [dq] CRT exponent of the second factor
 * @prop {BASE64URLUINT<any>} [qi] CRT coefficient of the second factor
 * @prop {RSAOtherPrimeInfo[]} [oth] an array of
 * information about any third and subsequent primes, should they exist.
 * When only two primes have been used (the normal case), this parameter
 * MUST be omitted.  When three or more primes have been used, the
 * number of array elements MUST be the number of primes used minus two.
 * For more information on this case, see the description of the
 * OtherPrimeInfo parameters in Appendix A.1.2 of RFC 3447 [RFC3447],
 * upon which the following parameters are modeled.  If the consumer of
 * a JWK does not support private keys with more than two primes and it
 * encounters a private key that includes the "oth" parameter, then it
 * MUST NOT use the key.  Each array element MUST be an object with the
 * following members.
 */

/**
 * @typedef {Object} RSAPublicKeyFields
 * @prop {'RSA'} kty Key type
 * @prop {BASE64URLUINT<any>} n (modulus) parameter contains the modulus
 * value for the RSA public key.
 *
 * Note that implementers have found that some cryptographic libraries
 * prefix an extra zero-valued octet to the modulus representations they
 * return, for instance, returning 257 octets for a 2048-bit key, rather
 * than 256.  Implementations using such libraries will need to take
 * care to omit the extra octet from the base64url-encoded
 * representation.
 * @prop {BASE64URL<Uint8Array>} e (exponent) parameter contains the exponent
 * value for the RSA public key.
 *
 * For instance, when representing the value 65537, the octet sequence
 * to be base64url-encoded MUST consist of the three octets [1, 0, 1];
 * the resulting representation for this value is "AQAB".
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1
 * @typedef {JWK & RSAPublicKeyFields} RSAPublicKey
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2
 * @typedef {RSAPublicKey & RSAPrivateKeyFields} RSAPrivateKey
 */

/**
 * JWKs can represent RSA [RFC3447] keys.  In this case, the "kty"
 * member value is "RSA".  The semantics of the parameters defined below
 * are the same as those defined in Sections 3.1 and 3.2 of RFC 3447.
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.3
 * @typedef {RSAPublicKey | RSAPrivateKey} RSAKey
 */

/**
 * @typedef {Object} SymmetricKeyFields
 * @prop {'oct'} kty octet sequence
 * @prop {BASE64URL<any>} k key value
 * The "k" (key value) parameter contains the value of the symmetric (or
 * other single-valued) key.
 */

