/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2
 * @typedef {Object} Account
 * @prop {'valid'|'deactivated'|'revoked'} status The status of this account.
 * The value "deactivated" should be used to indicate client-initiated
 * deactivation whereas "revoked" should be used to indicate server-
 * initiated deactivation.  See Section 7.1.6.
 * @prop {string[]} [contact] An array of URLs that the
 * server can use to contact the client for issues related to this
 * account.  For example, the server may wish to notify the client
 * about server-initiated revocation or certificate expiration.  For
 * information on supported URL schemes, see Section 7.3.
 * @prop {boolean} [termsOfServiceAgreed] Including this field in a `newAccount`
 * request, with a value of true, indicates the client's agreement with the
 * terms of service. This field cannot be updated by the client.
 * @prop {JWSJSONSerialization} [externalAccountBinding] Including this field in a
 * newAccount request indicates approval by the holder of an existing
 * non-ACME account to bind that account to this ACME account.  This
 * field is not updateable by the client (see Section 7.3.4).
 * @prop {string} orders A URL from which a list of orders
 * submitted by this account can be fetched via a POST-as-GET
 * request, as described in Section 7.1.2.1.
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
 * @typedef {Object} AccountNewRequestFields
 * @prop {boolean} [onlyReturnExisting] If this field is present
 *    with the value "true", then the server MUST NOT create a new
 *    account if one does not already exist.  This allows a client to
 *    look up an account URL based on an account key (see
 *    Section 7.3.1).
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
 * @typedef {Pick<Account, 'contact'|'termsOfServiceAgreed'|'externalAccountBinding'> & AccountNewRequestFields} AccountNewRequest
 */

/** @typedef {Pick<Account, 'status'|'contact'>} AccountRequest */
