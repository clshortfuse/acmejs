/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
 * @typedef {Object} Directory
 * @prop {string} newNonce New nonce
 * @prop {string} newAccount New account
 * @prop {string} newOrder New order
 * @prop {string} [newAuthz] New authorization
 * @prop {string} revokeCert Revoke certificate
 * @prop {string} keyChange Key change
 * @prop {DirectoryMeta} [meta] metadata relating to the service provided by
 * the ACME server
 */

/**
 * @typedef {Object} DirectoryMeta
 * @prop {string} [termsOfService] A URL identifying the
 * current terms of service.
 * @prop {string} [website] An HTTP or HTTPS URL locating a website providing
 * more information about the ACME server.
 * @prop {string[]} [caaIdentities] The hostnames that the
 * ACME server recognizes as referring to itself for the purposes of
 * CAA record validation as defined in [RFC6844].  Each string MUST
 * represent the same sequence of ASCII code points that the server
 * will expect to see as the "Issuer Domain Name" in a CAA issue or
 * issuewild property tag.  This allows clients to determine the
 * correct issuer domain name to use when configuring CAA records.
 * @prop {boolean} [externalAccountRequired] If this field is
 * present and set to "true", then the CA requires that all
 * newAccount requests include an "externalAccountBinding" field
 * associating the new account with an external account.
 */
