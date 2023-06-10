// https://www.rfc-editor.org/rfc/rfc7516.html

/**
 * For a JWE, the members of the JSON object(s) representing the JOSE
 * Header describe the encryption applied to the plaintext and
 * optionally additional properties of the JWE.  The Header Parameter
 * names within the JOSE Header MUST be unique, just as described in
 * Section 4 of [JWS].  The rules about handling Header Parameters that
 * are not understood by the implementation are also the same.  The
 * classes of Header Parameter names are likewise the same.
 * @see https://datatracker.ietf.org/doc/html/rfc7516#section-4
 * @typedef {Object} JWEJOSEHeader
 * @prop {string} alg algorithm
 * This parameter has the same meaning, syntax, and processing rules as
 * the "alg" Header Parameter defined in Section 4.1.1 of [JWS], except
 * that the Header Parameter identifies the cryptographic algorithm used
 * to encrypt or determine the value of the CEK.  The encrypted content
 * is not usable if the "alg" value does not represent a supported
 * algorithm, or if the recipient does not have a key that can be used
 * with that algorithm.
 * @prop {string} enc encryption algorithm
 * The "enc" (encryption algorithm) Header Parameter identifies the
 * content encryption algorithm used to perform authenticated encryption
 * on the plaintext to produce the ciphertext and the Authentication
 * Tag.  This algorithm MUST be an AEAD algorithm with a specified key
 * length.  The encrypted content is not usable if the "enc" value does
 * not represent a supported algorithm.  "enc" values should either be
 * registered in the IANA "JSON Web Signature and Encryption Algorithms"
 * registry established by [JWA] or be a value that contains a
 * Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII
 * string containing a StringOrURI value.  This Header Parameter MUST be
 * present and MUST be understood and processed by implementations.
 *
 * A list of defined "enc" values for this use can be found in the IANA
 * "JSON Web Signature and Encryption Algorithms" registry established
 * by [JWA]; the initial contents of this registry are the values
 * defined in Section 5.1 of [JWA].
 * @prop {'DEF'} [zip] compression algorithm
 * The "zip" (compression algorithm) applied to the plaintext before
 * encryption, if any.  The "zip" value defined by this specification
 * is:
 *
 * o  "DEF" - Compression with the DEFLATE [RFC1951] algorithm
 *
 * Other values MAY be used.  Compression algorithm values can be
 * registered in the IANA "JSON Web Encryption Compression Algorithms"
 * registry established by [JWA].  The "zip" value is a case-sensitive
 * string.  If no "zip" parameter is present, no compression is applied
 * to the plaintext before encryption.  When used, this Header Parameter
 * MUST be integrity protected; therefore, it MUST occur only within the
 * JWE Protected Header.  Use of this Header Parameter is OPTIONAL.
 * This Header Parameter MUST be understood and processed by
 * implementations.
 * @prop {string} jku JWK Set URL
 * This parameter has the same meaning, syntax, and processing rules as
 * the "jku" Header Parameter defined in Section 4.1.2 of [JWS], except
 * that the JWK Set resource contains the public key to which the JWE
 * was encrypted; this can be used to determine the private key needed
 * to decrypt the JWE.
 * @prop {JWK} jwk JSON Web Key
 * This parameter has the same meaning, syntax, and processing rules as
 * the "jwk" Header Parameter defined in Section 4.1.3 of [JWS], except
 * that the key is the public key to which the JWE was encrypted; this
 * can be used to determine the private key needed to decrypt the JWE.
 * @prop {string} kid Key ID
 * This parameter has the same meaning, syntax, and processing rules as
 * the "kid" Header Parameter defined in Section 4.1.4 of [JWS], except
 * that the key hint references the public key to which the JWE was
 * encrypted; this can be used to determine the private key needed to
 * decrypt the JWE.  This parameter allows originators to explicitly
 * signal a change of key to JWE recipients.
 * @prop {string} x5u X.509 URL
 * This parameter has the same meaning, syntax, and processing rules as
 * the "x5u" Header Parameter defined in Section 4.1.5 of [JWS], except
 * that the X.509 public key certificate or certificate chain [RFC5280]
 * contains the public key to which the JWE was encrypted; this can be
 * used to determine the private key needed to decrypt the JWE.
 * @prop {BASE64<any>} x5c X.509 Certificate Chain
 * This parameter has the same meaning, syntax, and processing rules as
 * the "x5c" Header Parameter defined in Section 4.1.6 of [JWS], except
 * that the X.509 public key certificate or certificate chain [RFC5280]
 * contains the public key to which the JWE was encrypted; this can be
 * used to determine the private key needed to decrypt the JWE.
 * @prop {BASE64URL<any>} x5t X.509 Certificate SHA-1 Thumbprint
 * This parameter has the same meaning, syntax, and processing rules as
 * the "x5t" Header Parameter defined in Section 4.1.7 of [JWS], except
 * that the certificate referenced by the thumbprint contains the public
 * key to which the JWE was encrypted; this can be used to determine the
 * private key needed to decrypt the JWE.  Note that certificate
 * thumbprints are also sometimes known as certificate fingerprints.
 * @prop {BASE64URL<any>} [x5t\u0023S256] X.509 Certificate SHA-256 Thumbprint
 * This parameter has the same meaning, syntax, and processing rules as
 * the "x5t#S256" Header Parameter defined in Section 4.1.8 of [JWS],
 * except that the certificate referenced by the thumbprint contains the
 * public key to which the JWE was encrypted; this can be used to
 * determine the private key needed to decrypt the JWE.  Note that
 * certificate thumbprints are also sometimes known as certificate
 * fingerprints.
 * @prop {string} [typ] Type
 * This parameter has the same meaning, syntax, and processing rules as
 * the "typ" Header Parameter defined in Section 4.1.9 of [JWS], except
 * that the type is that of this complete JWE.
 * @prop {string} [cty] Content Type
 * This parameter has the same meaning, syntax, and processing rules as
 * the "cty" Header Parameter defined in Section 4.1.10 of [JWS], except
 * that the type is that of the secured content (the plaintext).
 * @prop {(keyof JWEJOSEHeader)[]} [crit] Critical
 * This parameter has the same meaning, syntax, and processing rules as
 * the "crit" Header Parameter defined in Section 4.1.11 of [JWS],
 * except that Header Parameters for a JWE are being referred to, rather
 * than Header Parameters for a JWS.
 */

/**
 * JSON object that contains the Header Parameters that are integrity protected
 * by the authenticated encryption operation. These parameters apply to all
 * recipients of the JWE. For the JWE Compact Serialization, this comprises the
 * entire JOSE Header. For the JWE JSON Serialization, this is one component of
 * the JOSE Header.
 * @typedef {Record<string,any>} JWEProtectedHeader
 */

/**
 * JSON object that contains the Header Parameters that apply to all recipients
 * of the JWE that are not integrity protected. This can only be present when
 * using the JWE JSON Serialization.
 * @typedef {Record<string,any>} JWESharedUnprotectedHeader
 */

/**
 * JSON object that contains Header Parameters that apply to a single recipient
 * of the JWE. These Header Parameter values are not integrity protected. This
 * can only be present when using the JWE JSON Serialization.
 * @typedef {Record<string,any>} JWEPerRecipientUnprotectedHeader
 */

/**
 * Encrypted Content Encryption Key value.  Note that for some
 * algorithms, the JWE Encrypted Key value is specified as being the
 * empty octet sequence.
 * @typedef {any} JWEEncryptedKey
 */

/** @typedef {any} JWEInitializationVector */

/**
 * Ciphertext value resulting from authenticated encryption of the plaintext
 * with Additional Authenticated Data.
 * @typedef {any} JWECiphertext
 */

/** @typedef {any} JWEPlaintext */

/**
 * An output of an AEAD operation that ensures the integrity of the ciphertext
 * and the Additional Authenticated Data.  Note that some algorithms may not use
 * an Authentication Tag, in which case this value is the empty octet sequence.
 * @typedef {any} JWEAuthenticationTag
 */

/**
 * An input to an AEAD operation that is integrity protected but not encrypted.
 * @typedef {any} JWEAAD
 */

/**
 * @typedef {Object} JWERecipient
 * @prop {JWEPerRecipientUnprotectedHeader} [header]
 * @prop {BASE64URL<JWEEncryptedKey>} [encrypted_key]
 */

/**
 * A data structure representing an encrypted and integrity-protected message.
 * @typedef {Object} JWEGeneralBase
 * @prop {BASE64URL<UTF8<JWEProtectedHeader>>} [protected] BASE64URL(UTF8(JWE Protected Header))
 * @prop {JWESharedUnprotectedHeader} [unprotected] JWE Shared Unprotected Header
 * @prop {BASE64URL<JWEInitializationVector>} [iv] BASE64URL(JWE Initialization Vector)
 * @prop {BASE64URL<JWECiphertext>} ciphertext BASE64URL(JWE Ciphertext)
 * @prop {BASE64URL<JWECiphertext>} [tag] BASE64URL(JWE Tag)
 * @prop {BASE64URL<JWEAAD>} [aad] BASE64URL(JWE AAD)
 * @prop {JWERecipient[]} recipients Each object contains information specific
 * to a single recipient. This member MUST be present with exactly one array
 * element per recipient, even if some or all of the array element values are
 * the empty JSON object "{}" (which can happen when all Header Parameter values
 * are shared between all recipients and when no encrypted key is used, such as
 * when doing Direct Encryption).
 */

/** @typedef {JWEGeneralBase & (Required<Pick<JWEGeneralBase,'protected'>> | Required<Pick<JWEGeneralBase,'unprotected'>> | Required<Pick<JWEGeneralBase,'iv'>>)} JWEGeneral */

/** @typedef {Omit<JWEGeneral,'recipients'> & {recipients?:never} & JWERecipient} JWEFlattened */

/**
 * A representation of the JWE as a compact, URL-safe string.
 * @typedef {`${BASE64URL<UTF8<JWEProtectedHeader>>}.${BASE64URL<JWEEncryptedKey>}.${BASE64URL<JWEInitializationVector>}.${BASE64URL<JWECiphertext>}.${BASE64URL<JWEAuthenticationTag>}`} JWECompactSerialization
 */

/** @typedef {JWEFlattened | (JWEGeneral & Partial<Record<keyof JWERecipient,never>>)} JWEJSONSerialization */

/** @typedef {JWECompactSerialization | JWEJSONSerialization} JWE */

/**
 * A Key Management Mode in which the CEK value is encrypted to the
 * intended recipient using an asymmetric encryption algorithm.
 * @typedef {'keyEncryption'} KeyEncryption
 */

/**
 * A Key Management Mode in which the CEK value is encrypted to the
 * intended recipient using a symmetric key wrapping algorithm.
 * @typedef {'keyWrapping'} KeyWrapping
 */

/**
 * A Key Management Mode in which a key agreement algorithm is used
 * to agree upon the CEK value.
 * @typedef {'directKeyAgreement'} DirectKeyAgreement
 */

/**
 * A Key Management Mode in which a key agreement algorithm is used
 * to agree upon a symmetric key used to encrypt the CEK value to the intended recipient using a symmetric key wrapping algorithm.
 * @typedef {'keyAgreementWithKeyWrapping'} KeyAgreementWithKeyWrapping
 */

/**
 * A Key Management Mode in which the CEK value used is the secret
 * symmetric key value shared between the parties.
 * @typedef {'directEncryption'} DirectEncryption
 */

/**
 * A method of determining the Content Encryption Key value to use.
 * Each algorithm used for determining the CEK value uses a specific
 * Key Management Mode.
 * @typedef {KeyEncryption|KeyWrapping|DirectKeyAgreement|KeyAgreementWithKeyWrapping|DirectEncryption} KeyManagementMode
 */

/**
 *
 */
function test(p) {
  /** @type {JWEJSONSerialization} */
  const jwe = {
    ciphertext: 'text',
    recipients: [],
    iv: '',
  };

  /** @type {JWEJSONSerialization} */
  const jwe2 = {
    ciphertext: 'text',
    header: {},
    encrypted_key: '',
    iv: '',
  };
  return jwe;
}
