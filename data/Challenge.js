/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
 * @typedef {Object} ChallengeBase
 * @prop {string} url The URL to which a response can be posted.
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
 * @typedef {Object} PendingChallenge
 * @prop {'pending'} status The type of challenge encoded in the object.
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
 * @typedef {Object} ProcessingChallenge
 * @prop {'processing'} status The type of challenge encoded in the object.
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-8
 * @typedef {Object} ValidChallenge
 * @prop {'valid'} status The type of challenge encoded in the object.
 * @prop {string} validated The time at which the server validated
 *    this challenge, encoded in the format specified in [RFC3339].
 *    This field is REQUIRED if the "status" field is "valid".
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-8
 * @typedef {Object} InvalidChallenge
 * @prop {'invalid'} status The type of challenge encoded in the object.
 * @prop {ACMEError} error Error that occurred while the server was
 *    validating the challenge, if any, structured as a problem document
 *    [RFC7807].  Multiple errors can be indicated by using subproblems
 *    Section 6.7.1.  A challenge object with an error MUST have status
 *    equal to "invalid".
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-8.3
 * @typedef {Object} HttpChallenge
 * @prop {'http-01'} type The string "http-01".
 * @prop {BASE64URL<any>} token A random value that uniquely identifies
 *    the challenge.  This value MUST have at least 128 bits of entropy.
 *    It MUST NOT contain any characters outside the base64url alphabet
 *    and MUST NOT include base64 padding characters ("=").  See
 *    [RFC4086] for additional information on randomness requirements.
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-8.3
 * @typedef {Object} DNSChallenge
 * @prop {'dns-01'} type The string "dns-01".
 * @prop {BASE64URL<any>} token A random value that uniquely identifies
 *    the challenge.  This value MUST have at least 128 bits of entropy.
 *    It MUST NOT contain any characters outside the base64url alphabet
 *    and MUST NOT include base64 padding characters ("=").  See
 *    [RFC4086] for additional information on randomness requirements.
 */

/** @typedef {ChallengeBase&(ProcessingChallenge|PendingChallenge|ValidChallenge|InvalidChallenge)&(HttpChallenge|DNSChallenge)} Challenge */
