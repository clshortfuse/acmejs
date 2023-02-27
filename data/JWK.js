// https://datatracker.ietf.org/doc/html/rfc7517

/**
 *  A JWK is a JSON object that represents a cryptographic key.  The
 * members of the object represent properties of the key, including its
 * value.
 * @see https://datatracker.ietf.org/doc/html/rfc7517#section-4
 * @typedef {Object} JWK
 * @prop {string} kty key type
 * The "kty" (key type) parameter identifies the cryptographic algorithm
 * family used with the key, such as "RSA" or "EC".  "kty" values should
 * either be registered in the IANA "JSON Web Key Types" registry
 * established by [JWA] or be a value that contains a Collision-
 * Resistant Name.  The "kty" value is a case-sensitive string.  This
 * member MUST be present in a JWK.
 *
 * A list of defined "kty" values can be found in the IANA "JSON Web Key
 * Types" registry established by [JWA]; the initial contents of this
 * registry are the values defined in Section 6.1 of [JWA].
 *
 * The key type definitions include specification of the members to be
 * used for those key types.  Members used with specific "kty" values
 * can be found in the IANA "JSON Web Key Parameters" registry
 * @prop {'sig'|'enc'} [use] public use key
 * The "use" (public key use) parameter identifies the intended use of
 * the public key.  The "use" parameter is employed to indicate whether
 * a public key is used for encrypting data or verifying the signature
 * on data.
 *
 * Values defined by this specification are:
 *
 * o  "sig" (signature)
 * o  "enc" (encryption)
 *
 * Other values MAY be used.  The "use" value is a case-sensitive
 * string.  Use of the "use" member is OPTIONAL, unless the application
 * requires its presence.
 *
 * When a key is used to wrap another key and a public key use
 * designation for the first key is desired, the "enc" (encryption) key
 * use value is used, since key wrapping is a kind of encryption.  The
 * "enc" value is also to be used for public keys used for key agreement
 * operations.
 *
 * Additional "use" (public key use) values can be registered in the
 * IANA "JSON Web Key Use" registry established by Section 8.2.
 * Registering any extension values used is highly recommended when this
 * specification is used in open environments, in which multiple
 * organizations need to have a common understanding of any extensions
 * used.  However, unregistered extension values can be used in closed
 * environments, in which the producing and consuming organization will
 * always be the same.
 * @prop {('decrypt'|'deriveBits'|'deriveKey'|'encrypt'|'sign'|'unwrapKey'|'verify'|'wrapKey')[]} [key_ops] key operations
 * The "key_ops" (key operations) parameter identifies the operation(s)
 * for which the key is intended to be used.  The "key_ops" parameter is
 * intended for use cases in which public, private, or symmetric keys
 * may be present.
 *
 * Its value is an array of key operation values.  Values defined by
 * this specification are:
 *
 * o  "sign" (compute digital signature or MAC)
 * o  "verify" (verify digital signature or MAC)
 * o  "encrypt" (encrypt content)
 * o  "decrypt" (decrypt content and validate decryption, if applicable)
 * o  "wrapKey" (encrypt key)
 * o  "unwrapKey" (decrypt key and validate decryption, if applicable)
 * o  "deriveKey" (derive key)
 * o  "deriveBits" (derive bits not to be used as a key)
 *
 * (Note that the "key_ops" values intentionally match the "KeyUsage"
 * values defined in the Web Cryptography API
 * [W3C.CR-WebCryptoAPI-20141211] specification.)
 *
 * Other values MAY be used.  The key operation values are case-
 * sensitive strings.  Duplicate key operation values MUST NOT be
 * present in the array.  Use of the "key_ops" member is OPTIONAL,
 * unless the application requires its presence.
 *
 * Multiple unrelated key operations SHOULD NOT be specified for a key
 * because of the potential vulnerabilities associated with using the
 * same key with multiple algorithms.  Thus, the combinations "sign"
 * with "verify", "encrypt" with "decrypt", and "wrapKey" with
 * "unwrapKey" are permitted, but other combinations SHOULD NOT be used.
 *
 * Additional "key_ops" (key operations) values can be registered in the
 * IANA "JSON Web Key Operations" registry established by Section 8.3.
 * The same considerations about registering extension values apply to
 * the "key_ops" member as do for the "use" member.
 *
 * The "use" and "key_ops" JWK members SHOULD NOT be used together;
 * however, if both are used, the information they convey MUST be
 * consistent.  Applications should specify which of these members they
 * use, if either is to be used by the application.
 * @prop {string} [alg] algorithm
 * The "alg" (algorithm) parameter identifies the algorithm intended for
 * use with the key.  The values used should either be registered in the
 * IANA "JSON Web Signature and Encryption Algorithms" registry
 * established by [JWA] or be a value that contains a Collision-
 * Resistant Name.  The "alg" value is a case-sensitive ASCII string.
 * Use of this member is OPTIONAL.
 * @prop {string} [kid] key ID
 * The "kid" (key ID) parameter is used to match a specific key.  This
 * is used, for instance, to choose among a set of keys within a JWK Set
 * during key rollover.  The structure of the "kid" value is
 * unspecified.  When "kid" values are used within a JWK Set, different
 * keys within the JWK Set SHOULD use distinct "kid" values.  (One
 * example in which different keys might use the same "kid" value is if
 * they have different "kty" (key type) values but are considered to be
 * equivalent alternatives by the application using them.)  The "kid"
 * value is a case-sensitive string.  Use of this member is OPTIONAL.
 * When used with JWS or JWE, the "kid" value is used to match a JWS or
 * JWE "kid" Header Parameter value.
 * @prop {string} [x5u] X.509 URL
 * The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a
 * resource for an X.509 public key certificate or certificate chain
 * [RFC5280].  The identified resource MUST provide a representation of
 * the certificate or certificate chain that conforms to RFC 5280
 * [RFC5280] in PEM-encoded form, with each certificate delimited as
 * specified in Section 6.1 of RFC 4945 [RFC4945].  The key in the first
 * certificate MUST match the public key represented by other members of
 * the JWK.  The protocol used to acquire the resource MUST provide
 * integrity protection; an HTTP GET request to retrieve the certificate
 * MUST use TLS [RFC2818] [RFC5246]; the identity of the server MUST be
 * validated, as per Section 6 of RFC 6125 [RFC6125].  Use of this
 * member is OPTIONAL.
 *
 * While there is no requirement that optional JWK members providing key
 * usage, algorithm, or other information be present when the "x5u"
 * member is used, doing so may improve interoperability for
 * applications that do not handle PKIX certificates [RFC5280].  If
 * other members are present, the contents of those members MUST be
 * semantically consistent with the related fields in the first
 * certificate.  For instance, if the "use" member is present, then it
 * MUST correspond to the usage that is specified in the certificate,
 * when it includes this information.  Similarly, if the "alg" member is
 * present, it MUST correspond to the algorithm specified in the
 * certificate.
 * @prop {string} [x5c] X.509 Certificate Chain
 * The "x5c" (X.509 certificate chain) parameter contains a chain of one
 * or more PKIX certificates [RFC5280].  The certificate chain is
 * represented as a JSON array of certificate value strings.  Each
 * string in the array is a base64-encoded (Section 4 of [RFC4648] --
 * not base64url-encoded) DER [ITU.X690.1994] PKIX certificate value.
 * The PKIX certificate containing the key value MUST be the first
 * certificate.  This MAY be followed by additional certificates, with
 * each subsequent certificate being the one used to certify the
 * previous one.  The key in the first certificate MUST match the public
 * key represented by other members of the JWK.  Use of this member is
 * OPTIONAL.
 *
 * As with the "x5u" member, optional JWK members providing key usage,
 * algorithm, or other information MAY also be present when the "x5c"
 * member is used.  If other members are present, the contents of those
 * members MUST be semantically consistent with the related fields in
 * the first certificate.  See the last paragraph of Section 4.6 for
 * additional guidance on this.
 * @prop {string} [x5t] X.509 Certificate SHA-1 Thumbprint
 * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a
 * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
 * encoding of an X.509 certificate [RFC5280].  Note that certificate
 * thumbprints are also sometimes known as certificate fingerprints.
 * The key in the certificate MUST match the public key represented by
 * other members of the JWK.  Use of this member is OPTIONAL.
 *
 * As with the "x5u" member, optional JWK members providing key usage,
 * algorithm, or other information MAY also be present when the "x5t"
 * member is used.  If other members are present, the contents of those
 * members MUST be semantically consistent with the related fields in
 * the referenced certificate.  See the last paragraph of Section 4.6
 * for additional guidance on this.
 * @prop {string} [x5t\u0023S256] X.509 Certificate SHA-256 Thumbprint
 * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a
 * base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER
 * encoding of an X.509 certificate [RFC5280].  Note that certificate
 * thumbprints are also sometimes known as certificate fingerprints.
 * The key in the certificate MUST match the public key represented by
 * other members of the JWK.  Use of this member is OPTIONAL.
 *
 * As with the "x5u" member, optional JWK members providing key usage,
 * algorithm, or other information MAY also be present when the
 * "x5t#S256" member is used.  If other members are present, the
 * contents of those members MUST be semantically consistent with the
 * related fields in the referenced certificate.  See the last paragraph
 * of Section 4.6 for additional guidance on this.
 */

/** @typedef {JWK[]} JWKSet */

/**
 * @typedef {Object} JWAHeaderSignatureOrMac
 * @prop {'none'|`${'HS'|'RS'|'ES'|'PS'}${'256'|'384'|'512'}`} alg
 */

/**
 * @typedef {Object} EphemeralPublicKeyEllipticCurveAny
 * @prop {'EC'} kty Key type
 * @prop {string} crv the cryptographic curve used with the key.
 * @prop {string} x x coordinate for the Elliptic Curve point.
 * @prop {string} [y] y coordinate for the Elliptic Curve point.
 */

/**
 * @typedef {Object} EphemeralPublicKeyEdwardsCurve
 * @prop {'OKP'} kty Key type
 * @prop {`Ed${'25519'|'448'}`} crv signature algorithm
 * @prop {string} x x coordinate for the Elliptic Curve point.
 * @prop {string} [y] y coordinate for the Elliptic Curve point.
 */

/**
 * @typedef {Object} EphemeralPublicKeyEllipticCurveP
 * @prop {'EC'} kty Key type
 * @prop {`P-${'256'|'384'|'521'}`} crv the cryptographic curve used with the key.
 * @prop {string} x x coordinate for the Elliptic Curve point.
 * @prop {string} y y coordinate for the Elliptic Curve point.
 */

/**
 * @typedef {Object} EphemeralPublicKeyEllipticCurvePrivateKeys
 * @prop {string} d (ECC Private Key) Parameter
 */

/** @typedef {(EphemeralPublicKeyEllipticCurveAny|EphemeralPublicKeyEllipticCurveP) & Partial<EphemeralPublicKeyEllipticCurvePrivateKeys>} EphemeralPublicKeyEllipticCurve */

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
 * @typedef {Object} JWSHeaderBase
 * @prop {string} nonce a unique value that enables the verifier of a JWS to
 * recognize when replay has occurred.
 * @prop {string} url URL [RFC3986] to which this JWS object is directed
 */

/**
 * @template {JWAHeader} [T=JWAHeader]
 * @typedef {JWSHeaderBase & Pick<T,'alg'> & ({jwk:Omit<T,'alg'>} | {kid:string})} JWSHeader
 */
