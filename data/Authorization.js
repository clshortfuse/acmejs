/**
 * @typedef {Object} AuthorizationIdentifier
 * @prop {'dns'} type The type of identifier.
 * @prop {string} value The identifier itself.
 */

/**
 * @template {'pending'|'valid'|'invalid'|'deactivated'|'expired'|'revoked'} [S=any]
 * @template {Object} [T={}]
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
 * @typedef {Object} Authorization
 * @prop {AuthorizationIdentifier} identifier The identifier that the account is
 * authorized to represent.
 * @prop {S} status The status of this authorization.  See Section 7.1.6.
 * @prop {S extends 'valid' ? string : (?string) } expires The timestamp after
 * which the server will consider this authorization invalid, encoded in the
 * format specified in [RFC3339].
 * @prop {Challenge[]} challenges For pending authorizations,
 *    the challenges that the client can fulfill in order to prove
 *    possession of the identifier.  For valid authorizations, the
 *    challenge that was validated.  For invalid authorizations, the
 *    challenge that was attempted and failed.  Each array entry is an
 *    object with parameters required to validate the challenge.  A
 *    client should attempt to fulfill one of these challenges, and a
 *    server should consider any one of the challenges sufficient to
 *    make the authorization valid.
 * @prop {boolean} [wildcard] This field MUST be present and true
 *    for authorizations created as a result of a newOrder request
 *    containing a DNS identifier with a value that was a wildcard
 *    domain name.  For other authorizations, it MUST be absent.
 *    Wildcard domain names are described in Section 7.1.3.
 */
