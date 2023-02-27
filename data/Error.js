/** @typedef {'accountDoesNotExist'} accountDoesNotExist The request specified an account that does not exist */
/** @typedef {'alreadyRevoked'} alreadyRevoked The request specified a certificate to be revoked that has already been revoked */
/** @typedef {'badCSR'} badCSR The CSR is unacceptable (e.g., due to a short key) */
/** @typedef {'badNonce'} badNonce The client sent an unacceptable anti-replay nonce */
/** @typedef {'badPublicKey'} badPublicKey The JWS was signed by a public key the server does not support */
/** @typedef {'badRevocationReason'} badRevocationReason The revocation reason provided is not allowed by the server */
/** @typedef {'badSignatureAlgorithm'} badSignatureAlgorithm The JWS was signed with an algorithm the server does not support */
/** @typedef {'caa'} caa Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate */
/** @typedef {'compound'} compound Specific error conditions are indicated in the "subproblems" array */
/** @typedef {'connection'} connection The server could not connect to validation target */
/** @typedef {'dns'} dns There was a problem with a DNS query during identifier validation */
/** @typedef {'externalAccountRequired'} externalAccountRequired The request must include a value for the "externalAccountBinding" field */
/** @typedef {'incorrectResponse'} incorrectResponse Response received didn't match the challenge's requirements */
/** @typedef {'invalidContact'} invalidContact A contact URL for an account was invalid */
/** @typedef {'malformed'} malformed The request message was malformed */
/** @typedef {'orderNotReady'} orderNotReady The request attempted to finalize an order that is not ready to be finalized */
/** @typedef {'rateLimited'} rateLimited The request exceeds a rate limit */
/** @typedef {'rejectedIdentifier'} rejectedIdentifier The server will not issue certificatefor the identifier */
/** @typedef {'serverInternal'} serverInternal The server experienced an internal error */
/** @typedef {'tls'} tls The server received a TLS error durinvalidation */
/** @typedef {'unauthorized'} unauthorized The client lacks sufficient authorization */
/** @typedef {'unsupportedContact'} unsupportedContact A contact URL for an account used an unsupported protocol scheme */
/** @typedef {'unsupportedIdentifier'} unsupportedIdentifier An identifier is of an unsupported type */
/** @typedef {'userActionRequired'} userActionRequired Visit the "instance" URL and take actions specified there */

/** @typedef {accountDoesNotExist|alreadyRevoked|badCSR|badNonce|badPublicKey|badRevocationReason|badSignatureAlgorithm|caa|compound|connection|dns|externalAccountRequired|incorrectResponse|invalidContact|malformed|orderNotReady|rateLimited|rejectedIdentifier|serverInternal|tls|unauthorized|unsupportedContact|unsupportedIdentifier|userActionRequired} ErrorType */

/**
 * @typedef {Object} SubproblemIdentifier
 * @prop {'dns'} type The type of identifier.
 * @prop {string} value The identifier itself.
 */

/**
 * @typedef {Object} Subproblem
 * @prop {`urn:ietf:params:acme:error:${ErrorType}`} type
 * @prop {string} detail
 * @prop {SubproblemIdentifier} identifier
 */

/**
 * @typedef {Object} ACMEError
 * @prop {`urn:ietf:params:acme:error:${ErrorType}`} type
 * @prop {string} detail
 * @prop {Subproblem[]} subproblems
 */
