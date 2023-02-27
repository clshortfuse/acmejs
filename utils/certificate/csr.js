import { extractPublicJWK, parseAlgorithmIdentifier } from '../../lib/jwa.js';
import {
  ASN_CLASS, ASN_CONSTRUCTED,
  encodeAttribute, encodeBitString, encodeDER, encodeDNSName, encodeExtension,
  encodeExtensions, encodeInteger, encodeObjectIdentifier, encodePrintableString,
  encodeSequence, encodeSet, encodeSubjectAltNameValue, encodeUTF8String,
  parseSignatureAlgorithm,
} from '../asn1.js';
import { importJWK, sign } from '../crypto.js';

import { derFromPEM, pemFromDER } from './format.js';
import { derFromSPKI, spkiFromJWK } from './publicKey.js';

const CSR_HEADER = '-----BEGIN CERTIFICATE REQUEST-----';
const CSR_FOOTER = '-----END CERTIFICATE REQUEST-----';

/**
 * @param {string|Uint8Array} csr
 * @return {Uint8Array}
 */
export function derFromCSR(csr) {
  if (typeof csr !== 'string') return csr;
  return derFromPEM(csr, CSR_HEADER, CSR_FOOTER);
}

/**
 * @param {string|Uint8Array} csr
 * @return {string}
 */
export function pemFromCSR(csr) {
  return pemFromDER(derFromCSR(csr), CSR_HEADER, CSR_FOOTER);
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc2986
 * @see https://datatracker.ietf.org/doc/html/rfc2985#section-5.4 (Attributes)
 * @see https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1 (Extensions)
 * @param {Object} options
 * @param {string} options.commonName
 * @param {string} [options.organizationName]
 * @param {string} [options.organizationalUnitName]
 * @param {string} [options.localityName]
 * @param {string} [options.stateOrProvinceName]
 * @param {string} [options.countryName]
 * @param {string[]} [options.altNames]
 * @param {JWK} options.jwk
 * @return {Promise<Uint8Array>}
 */
export async function createCSR(options) {
  /** @type {[string,string,(input: string) => number[]][]} */
  const oidMappings = [
    ['2.5.4.3', options.commonName, encodeUTF8String],
    ['2.5.4.6', options.countryName, encodePrintableString],
    ['2.5.4.7', options.localityName, encodeUTF8String],
    ['2.5.4.8', options.stateOrProvinceName, encodeUTF8String],
    ['2.5.4.10', options.organizationName, encodeUTF8String],
    ['2.5.4.11', options.organizationalUnitName, encodeUTF8String],
  ];
  // dn are composed as sets
  const dnSets = oidMappings
    .filter(([oid, value]) => value)
    .map(([oid, value, encoder]) => encodeSet(
      encodeSequence(
        encodeObjectIdentifier(oid),
        encoder(value),
      ),
    ));
  const subject = encodeSequence(...dnSets);

  const algorithmIdentifier = parseAlgorithmIdentifier(options.jwk);

  // Note: Could use ASN1 to compile SPKI, but using platform implementation is safer
  const spki = await spkiFromJWK(extractPublicJWK(options.jwk), algorithmIdentifier);
  const SubjectPKInfo = derFromSPKI(spki);

  let attributes;
  if (options.altNames?.length) {
    const extensionRequestAttributeOID = '1.2.840.113549.1.9.14';
    const subjectAltNameOID = '2.5.29.17';

    const attributesTag = 0;
    attributes = encodeDER(
      // eslint-disable-next-line no-bitwise
      ASN_CLASS.CONTEXT_SPECIFIC | ASN_CONSTRUCTED | attributesTag,
      encodeAttribute(
        extensionRequestAttributeOID,
        encodeExtensions(
          encodeExtension(
            subjectAltNameOID,
            encodeSubjectAltNameValue(
              ...options.altNames.map((dnsName) => encodeDNSName(dnsName)),
            ),
          ),
        ),
      ),
    );
  }

  const certificationRequestInfo = encodeSequence(
    encodeInteger(0), // Version
    subject, // Subject
    SubjectPKInfo, // SubjectPKInfo
    attributes ?? [], // Attributes,
  );

  const key = await importJWK({ ...options.jwk, key_ops: ['sign'] }, algorithmIdentifier);
  const signedCRI = await sign(algorithmIdentifier, key, Uint8Array.from(certificationRequestInfo));
  const dataArray = new Uint8Array(signedCRI);
  const signature = encodeBitString(dataArray, signedCRI.byteLength);
  const certificationRequest = encodeSequence(
    certificationRequestInfo,
    parseSignatureAlgorithm(options.jwk),
    signature,
  );
  return Uint8Array.from(certificationRequest);
}

/** @alias */
export const createPKCS10 = createCSR;
/** @alias */
export const derFromPKCS10 = derFromCSR;
/** @alias */
export const pemFromPKCS10 = pemFromCSR;
