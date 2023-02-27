// https://datatracker.ietf.org/doc/html/rfc7515

/**
 * @typedef {Object} JWSJOSEHeaderFields JSON object that contains
 * the Header Parameters that are not integrity protected.
 * @prop {string} alg (algorithm) Header Parameter identifies the cryptographic
 * algorithm used to secure the JWS.  The JWS Signature value is not
 * valid if the "alg" value does not represent a supported algorithm or
 * if there is not a key for use with that algorithm associated with the
 * party that digitally signed or MACed the content.  "alg" values
 * should either be registered in the IANA "JSON Web Signature and
 * Encryption Algorithms" registry established by [JWA] or be a value
 * that contains a Collision-Resistant Name.  The "alg" value is a case-
 * sensitive ASCII string containing a StringOrURI value.  This Header
 * Parameter MUST be present and MUST be understood and processed by
 * implementations.
 * @prop {string} [jku] JWK Set URL
 * A URI [RFC3986] that
 * refers to a resource for a set of JSON-encoded public keys, one of
 * which corresponds to the key used to digitally sign the JWS.  The
 * keys MUST be encoded as a JWK Set [JWK].  The protocol used to
 * acquire the resource MUST provide integrity protection; an HTTP GET
 * request to retrieve the JWK Set MUST use Transport Layer Security
 * (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be
 * validated, as per Section 6 of RFC 6125 [RFC6125].  Also, see
 * Section 8 on TLS requirements.  Use of this Header Parameter is
 * OPTIONAL.
 * @prop {JWK} [jwk] JSON Web Key
 * The "jwk" (JSON Web Key) Header Parameter is the public key that
 * corresponds to the key used to digitally sign the JWS.  This key is
 * represented as a JSON Web Key [JWK].  Use of this Header Parameter is
 * OPTIONAL.
 * @prop {string} [kid] Key ID
 * The "kid" (key ID) Header Parameter is a hint indicating which key
 * was used to secure the JWS.  This parameter allows originators to
 * explicitly signal a change of key to recipients.  The structure of
 * the "kid" value is unspecified.  Its value MUST be a case-sensitive
 * string.  Use of this Header Parameter is OPTIONAL.
 *
 * When used with a JWK, the "kid" value is used to match a JWK "kid"
 * parameter value.
 * @prop {string} [x5u] X.509 URL
 * The "x5u" (X.509 URL) Header Parameter is a URI [RFC3986] that refers
 * to a resource for the X.509 public key certificate or certificate
 * chain [RFC5280] corresponding to the key used to digitally sign the
 * JWS.  The identified resource MUST provide a representation of the
 * certificate or certificate chain that conforms to RFC 5280 [RFC5280]
 * in PEM-encoded form, with each certificate delimited as specified in
 * Section 6.1 of RFC 4945 [RFC4945].  The certificate containing the
 * public key corresponding to the key used to digitally sign the JWS
 * MUST be the first certificate.  This MAY be followed by additional
 * certificates, with each subsequent certificate being the one used to
 * certify the previous one.  The protocol used to acquire the resource
 * MUST provide integrity protection; an HTTP GET request to retrieve
 * the certificate MUST use TLS [RFC2818] [RFC5246]; and the identity of
 * the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].
 * Also, see Section 8 on TLS requirements.  Use of this Header
 * Parameter is OPTIONAL.
 * @prop {BASE64<any>} [x5c] X.509 Certificate Chain
 * The "x5c" (X.509 certificate chain) Header Parameter contains the
 * X.509 public key certificate or certificate chain [RFC5280]
 * corresponding to the key used to digitally sign the JWS.  The
 * certificate or certificate chain is represented as a JSON array of
 * certificate value strings.  Each string in the array is a
 * base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
 * [ITU.X690.2008] PKIX certificate value.  The certificate containing
 * the public key corresponding to the key used to digitally sign the
 * JWS MUST be the first certificate.  This MAY be followed by
 * additional certificates, with each subsequent certificate being the
 * one used to certify the previous one.  The recipient MUST validate
 * the certificate chain according to RFC 5280 [RFC5280] and consider
 * the certificate or certificate chain to be invalid if any validation
 * failure occurs.  Use of this Header Parameter is OPTIONAL.
 * @prop {BASE64URL<any>} [x5t] X.509 Certificate SHA-1 Thumbprint
 * The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
 * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
 * encoding of the X.509 certificate [RFC5280] corresponding to the key
 * used to digitally sign the JWS.  Note that certificate thumbprints
 * are also sometimes known as certificate fingerprints.  Use of this
 * Header Parameter is OPTIONAL.
 * @prop {BASE64URL<any>} [x5t\u0023S256] X.509 Certificate SHA-256 Thumbprint
 * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header
 * Parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
 * of the DER encoding of the X.509 certificate [RFC5280] corresponding
 * to the key used to digitally sign the JWS.  Note that certificate
 * thumbprints are also sometimes known as certificate fingerprints.
 * Use of this Header Parameter is OPTIONAL.
 * @prop {string} [typ] Type
 * The "typ" (type) Header Parameter is used by JWS applications to
 * declare the media type [IANA.MediaTypes] of this complete JWS.  This
 * is intended for use by the application when more than one kind of
 * object could be present in an application data structure that can
 * contain a JWS; the application can use this value to disambiguate
 * among the different kinds of objects that might be present.  It will
 * typically not be used by applications when the kind of object is
 * already known.  This parameter is ignored by JWS implementations; any
 * processing of this parameter is performed by the JWS application.
 * Use of this Header Parameter is OPTIONAL.
 *
 * Per RFC 2045 [RFC2045], all media type values, subtype values, and
 * parameter names are case insensitive.  However, parameter values are
 * case sensitive unless otherwise specified for the specific parameter.
 *
 * To keep messages compact in common situations, it is RECOMMENDED that
 * producers omit an "application/" prefix of a media type value in a
 * "typ" Header Parameter when no other '/' appears in the media type
 * value.  A recipient using the media type value MUST treat it as if
 * "application/" were prepended to any "typ" value not containing a
 * '/'.  For instance, a "typ" value of "example" SHOULD be used to
 * represent the "application/example" media type, whereas the media
 * type "application/example;part="1/2"" cannot be shortened to
 * "example;part="1/2"".
 *
 * The "typ" value "JOSE" can be used by applications to indicate that
 * this object is a JWS or JWE using the JWS Compact Serialization or
 * the JWE Compact Serialization.  The "typ" value "JOSE+JSON" can be
 * used by applications to indicate that this object is a JWS or JWE
 * using the JWS JSON Serialization or the JWE JSON Serialization.
 * Other type values can also be used by applications.
 * @prop {string} [cty] Content Type
 * The "cty" (content type) Header Parameter is used by JWS applications
 * to declare the media type [IANA.MediaTypes] of the secured content
 * (the payload).  This is intended for use by the application when more
 * than one kind of object could be present in the JWS Payload; the
 * application can use this value to disambiguate among the different
 * kinds of objects that might be present.  It will typically not be
 * used by applications when the kind of object is already known.  This
 * parameter is ignored by JWS implementations; any processing of this
 * parameter is performed by the JWS application.  Use of this Header
 * Parameter is OPTIONAL.
 *
 * Per RFC 2045 [RFC2045], all media type values, subtype values, and
 * parameter names are case insensitive.  However, parameter values are
 * case sensitive unless otherwise specified for the specific parameter.
 *
 * To keep messages compact in common situations, it is RECOMMENDED that
 * producers omit an "application/" prefix of a media type value in a
 * "cty" Header Parameter when no other '/' appears in the media type
 * value.  A recipient using the media type value MUST treat it as if
 * "application/" were prepended to any "cty" value not containing a
 * '/'.  For instance, a "cty" value of "example" SHOULD be used to
 * represent the "application/example" media type, whereas the media
 * type "application/example;part="1/2"" cannot be shortened to
 * "example;part="1/2"".
 * @prop {(keyof JWSJOSEHeaderFields)[]} [crit] Critical
 * The "crit" (critical) Header Parameter indicates that extensions to
 * this specification and/or [JWA] are being used that MUST be
 * understood and processed.  Its value is an array listing the Header
 * Parameter names present in the JOSE Header that use those extensions.
 * If any of the listed extension Header Parameters are not understood
 * and supported by the recipient, then the JWS is invalid.  Producers
 * MUST NOT include Header Parameter names defined by this specification
 * or [JWA] for use with JWS, duplicate names, or names that do not
 * occur as Header Parameter names within the JOSE Header in the "crit"
 * list.  Producers MUST NOT use the empty list "[]" as the "crit"
 * value.  Recipients MAY consider the JWS to be invalid if the critical
 * list contains any Header Parameter names defined by this
 * specification or [JWA] for use with JWS or if any other constraints
 * on its use are violated.  When used, this Header Parameter MUST be
 * integrity protected; therefore, it MUST occur only within the JWS
 * Protected Header.  Use of this Header Parameter is OPTIONAL.  This
 * Header Parameter MUST be understood and processed by implementations.
 *
 * An example use, along with a hypothetical "exp" (expiration time)
 * field is:
 *
 *   {"alg":"ES256",
 *    "crit":["exp"],
 *    "exp":1363284000
 *   }
 */

/**
 * JSON object containing the parameters describing the cryptographic
 * operations and parameters employed.  The JOSE (JSON Object Signing
 * and Encryption) Header is comprised of a set of Header Parameters.
 * @typedef {JWSProtectedHeader | JWSUnprotectedHeader | (JWSProtectedHeader & JWSUnprotectedHeader) } JWSJOSEHeader
 */

/**
 * @typedef {any} JWSPayload The sequence of octets to be secured -- a.k.a. the
 * message. The payload can contain an arbitrary sequence of octets.
 */

/**
 * @typedef {ArrayBuffer} JWSSignature Digital signature or MAC over the JWS Protected
 * Header and the JWS Payload.
 */

/**
 * @template {any} [T={}]
 * @typedef {JWSJOSEHeaderFields & T} JWSProtectedHeader JSON object that contains
 * the Header Parameters that are integrity protected by the JWS Signature
 * digital signature or MAC operation.
 */

/**
 * @template {any} [T={}]
 * @typedef {JWSJOSEHeaderFields & T} JWSUnprotectedHeader JSON object that contains
 * the Header Parameters that are not integrity protected.
 */

/**
 * The input to the digital signature or MAC computation.
 * @typedef {`${ASCII<BASE64URL<UTF8<JWSProtectedHeader>>>}.${BASE64URL<JWSPayload>}`} JWSSigningInput
 */

/**
 * @typedef {Object} JWSSignatureObjectBase
 * @prop {BASE64URL<UTF8<JWSProtectedHeader>>} [protected] BASE64URL(UTF8(JWS Protected Header))
 * @prop {JWSUnprotectedHeader} [header] JWS Unprotected Header
 * @prop {BASE64URL<JWSSignature>} signature BASE64URL(JWS Signature)
 */

/**
 * @typedef {JWSSignatureObjectBase & (Required<Pick<JWSSignatureObjectBase, 'protected'>> | Required<Pick<JWSSignatureObjectBase, 'header'>>)} JWSSignatureObject
 */

/**
 * A fully general JWS JSON Serialization with which content can be secured with
 * more than one digital signature and/or MAC operation
 * @typedef {Object} JWSGeneral
 * @prop {BASE64URL<JWSPayload>} payload
 * @prop {JWSSignatureObject[]} signatures
 */

/**
 * A flattened syntax which is optimized for the single digital signature or
 * MAC case.
 * @typedef {Omit<JWSGeneral,'signatures'> & {signatures?:never} & JWSSignatureObject} JWSFlattened
 */

/**
 * A representation of the JWE as a compact, URL-safe string.
 * @typedef {`${BASE64URL<UTF8<JWSProtectedHeader>>}.${BASE64URL<JWSPayload>}.${BASE64URL<JWSSignature>}`} JWSCompactSerialization
 */

/**
 * A representation of the JWS as a JSON object.  Unlike the JWS
 * Compact Serialization, the JWS JSON Serialization enables multiple
 * digital signatures and/or MACs to be applied to the same content.
 * This representation is neither optimized for compactness nor URL-
 * safe.
 * @typedef {JWSFlattened | (JWSGeneral & Partial<Record<keyof JWSSignatureObject,never>>)} JWSJSONSerialization
 */

/**
 * A data structure representing a digitally signed or MACed message.
 * @typedef {JWSCompactSerialization | JWSJSONSerialization} JWS
 */

/** @return {any} */
function test() {
  /** @type {JWSJSONSerialization} */
  let jws = {
    payload: 'payload',
    signatures: [],
  };

  /** @type {JWSJSONSerialization} */
  jws = {
    payload: 'payload',
    signature: 'abc',
    protected: '',
  };

  /** @type {JWSJSONSerialization} */
  jws = {
    payload: 'payload',
    signatures: [{
      signature: '',
      protected: '',
    }],
  };
  return jws;
}
