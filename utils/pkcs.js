import { extractPublicJWK, parseAlgorithmIdentifier } from '../lib/jwa.js';

import {
  ASN_CLASS, ASN_CONSTRUCTED, ASN_OID, encodeAlgorithmIdentifer, encodeAttribute,
  encodeBitString, encodeDER, encodeDNSName, encodeExtension, encodeExtensions,
  encodeInteger, encodeObjectIdentifier, encodeOctetString, encodePrintableString, encodeSequence,
  encodeSet, encodeSubjectAltNameValue, encodeUTF8String, parseSignatureAlgorithm,
} from './asn1.js';
import { decodeBase64AsArray, encodeBase64AsString } from './base64.js';
import { importJWK, sign, spkiFromJWK } from './crypto.js';

const PKCS1_HEADER = '-----BEGIN RSA PRIVATE KEY-----';
const PKCS1_FOOTER = '-----END RSA PRIVATE KEY-----';

const PKCS8_HEADER = '-----BEGIN PRIVATE KEY-----';
const PKCS8_FOOTER = '-----END PRIVATE KEY-----';

const PKCS10_HEADER = '-----BEGIN CERTIFICATE REQUEST-----';
const PKCS10_FOOTER = '-----END CERTIFICATE REQUEST-----';

const SPKI_HEADER = '-----BEGIN PUBLIC KEY-----';
const SPKI_FOOTER = '-----END PUBLIC KEY-----';

/**
 * @param {string} pem
 * @param {string} [header]
 * @param {string} [footer]
 * @return {Uint8Array}
 */
export function derFromPEM(pem, header, footer) {
  let content;
  if (!header || !footer) {
    const splits = pem.split('-----');
    if (splits.length === 1) {
      // No header, assume encoded DER
      content = pem;
    } else if (splits.length === 5) {
      content = splits[2];
    } else {
      throw new Error('Invalid PEM');
    }
  } else {
    const indexOfHeader = pem.indexOf(header);
    const indexOfFooter = pem.indexOf(footer);
    if (indexOfHeader !== -1 && indexOfFooter !== -1) {
      content = pem.slice(
        pem.indexOf(header) + header.length,
        pem.indexOf(footer),
      );
    } else if (indexOfHeader === -1 && indexOfHeader === -1) {
      // No header, assume encoded DER
      content = pem;
    } else {
      throw new Error('Invalid PEM!');
    }
  }
  return decodeBase64AsArray(content.replaceAll(/\s/g, ''));
}

/**
 * @param {Uint8Array} der
 * @param {string} header
 * @param {string} footer
 */
export function pemFromDER(der, header, footer) {
  return `${header}\n${encodeBase64AsString(der).replaceAll(/(.{64})/g, '$1\n')}\n${footer}`;
}

// -----BEGIN HELPER FUNCTIONS-----

/**
 * @param {string|Uint8Array} pkcs8 PEM or DER format
 * @return {Uint8Array} DER format
 */
export function derFromPKCS8(pkcs8) {
  if (typeof pkcs8 !== 'string') return pkcs8;
  return derFromPEM(pkcs8, PKCS8_HEADER, PKCS8_FOOTER);
}

/**
 * @param {string|Uint8Array} pkcs8
 * @return {string}
 */
export function pemFromPKCS8(pkcs8) {
  return pemFromDER(derFromPKCS8(pkcs8), PKCS8_HEADER, PKCS8_FOOTER);
}

/**
 * @param {string|Uint8Array} pkcs1
 * @return {Uint8Array}
 */
export function derFromPKCS1(pkcs1) {
  if (typeof pkcs1 !== 'string') return pkcs1;
  return derFromPEM(pkcs1, PKCS1_HEADER, PKCS1_FOOTER);
}

/**
 * @param {string|Uint8Array} pkcs1
 * @return {string}
 */
export function pemFromPKCS1(pkcs1) {
  return pemFromDER(derFromPKCS1(pkcs1), PKCS1_HEADER, PKCS1_FOOTER);
}

/**
 * @param {string|Uint8Array} spki
 * @return {Uint8Array}
 */
export function derFromSPKI(spki) {
  if (typeof spki !== 'string') return spki;
  return derFromPEM(spki, SPKI_HEADER, SPKI_FOOTER);
}

/**
 * @param {string|Uint8Array} spki
 * @return {string}
 */
export function pemFromSPKI(spki) {
  return pemFromDER(derFromSPKI(spki), SPKI_HEADER, SPKI_FOOTER);
}

/**
 * @param {string|Uint8Array} pkcs10
 * @return {Uint8Array}
 */
export function derFromPKCS10(pkcs10) {
  if (typeof pkcs10 !== 'string') return pkcs10;
  return derFromPEM(pkcs10, PKCS10_HEADER, PKCS10_FOOTER);
}

/**
 * @param {string|Uint8Array} pkcs10
 * @return {string}
 */
export function pemFromPKCS10(pkcs10) {
  return pemFromDER(derFromPKCS10(pkcs10), PKCS10_HEADER, PKCS10_FOOTER);
}

/**
 * Reconstructs PEM into with line breaks and 64 limit
 * @param {string} pem
 * @param {string} [header]
 * @param {string} [footer]
 * @return {string}
 */
export function formatPEM(pem, header, footer) {
  let content;
  if (!header || !footer) {
    const splits = pem.split('-----');
    if (splits.length !== 5) throw new Error('Invalid PEM');

    header = `-----${splits[1]}-----`;
    content = splits[2];
    footer = `-----${splits[3]}-----`;
  } else {
    const indexOfHeader = pem.indexOf(header);
    const indexOfFooter = pem.indexOf(footer);

    if (indexOfHeader !== -1 && indexOfFooter !== -1) {
      content = pem.slice(
        pem.indexOf(header) + header.length,
        pem.indexOf(footer),
      );
    } else if (indexOfHeader === -1 && indexOfHeader === -1) {
      // No header, assume encoded DER
      content = pem;
    } else {
      throw new Error('Invalid PEM!');
    }
  }
  return `${header}\n${content.replaceAll(/\s/g, '').replaceAll(/(.{64})/g, '$1\n')}\n${footer}`;
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * @param {string|Uint8Array} pkcs1
 * @return {Uint8Array}
 */
export function pkcs8FromPKCS1(pkcs1) {
  const der = derFromPKCS1(pkcs1);

  const privateKeyInfo = encodeSequence(
    encodeInteger(0), // Version

    encodeAlgorithmIdentifer(ASN_OID.rsaEncryption), // PrivateKeyAlgorithm

    encodeOctetString(der), // PrivateKey
  );
  return Uint8Array.from(privateKeyInfo);
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
export async function createPKCS10(options) {
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
export const createCSR = createPKCS10;
