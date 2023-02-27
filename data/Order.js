/**
 * @typedef {Object} OrderIdentifier
 * @prop {'dns'} type The type of identifier.
 * @prop {string} value The identifier itself.
 */

/**
 * @typedef {Object} ActiveOrder
 * @prop {'pending'|'valid'} status
 * @prop {string} expires
 * The timestamp after which the server will consider this order invalid,
 * encoded in the format specified in [RFC3339].
 */

/**
 * @typedef {Object} OtherOrder
 * @prop {'ready'|'processing'|'invalid'} status
 * @prop {string} [expires]
 * The timestamp after which the server will consider this order invalid,
 * encoded in the format specified in [RFC3339].
 */

/**
 * @template {'pending'|'ready'|'processing'|'valid'|'invalid'} [S=any]
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3
 * @typedef {Object} OrderBase
 * @prop {OrderIdentifier[]} identifiers An array of identifier objects that
 * the order pertains to.
 * @prop {string} [notBefore] The requested value of the notBefore field in the
 * certificate, in the date format defined in [RFC3339].
 * @prop {string} [notAfter] The requested value of the notAfter field in the
 * certificate, in the date format defined in [RFC3339].
 * @prop {Object} [error] The error that occurred while processing the order,
 * if any.  This field is structured as a problem document [RFC7807].
 * @prop {string[]} authorizations For pending orders, the authorizations that
 * the client needs to complete before the requested certificate can be issued
 * (see Section 7.5), including unexpired authorizations that the client has
 * completed in the past for identifiers specified in the order.
 * The authorizations required are dictated by server policy; there may not be
 * a 1:1 relationship between the order identifiers and the authorizations
 * required.  For final orders (in the "valid" or "invalid" state), the
 * authorizations that were completed.  Each entry is a URL from which an
 * authorization can be fetched with a POST-as-GET request.
 * @prop {string} finalize A URL that a CSR must be POSTed to once
 * all of the order's authorizations are satisfied to finalize the
 * order.  The result of a successful finalization will be the
 * population of the certificate URL for the order.
 * @prop {string} [certificate] A URL for the certificate that has
 * been issued in response to this order.
 */

/** @typedef {OrderBase&(ActiveOrder|OtherOrder)} Order */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
 * @typedef {Pick<Order, 'identifiers'|'notBefore'|'notAfter'>} OrderNewRequest
 */

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
 * @typedef {Object} OrderFinalizeRequest
 * @prop {BASE64URL<any>} csr  A CSR encoding the parameters for the
 * certificate being requested [RFC2986].  The CSR is sent in the
 * base64url-encoded version of the DER format.  (Note: Because this
 * field uses base64url, and does not include headers, it is
 * different from PEM.)
 */
