import { ASN_OID, decodeDER, readString } from '../asn1.js';

import { derFromPEM, pemFromDER } from './format.js';

/** Encryption not currently supported */

// https://datatracker.ietf.org/doc/html/rfc5280
const PKIX_HEADER = '-----BEGIN CERTIFICATE-----';
const PKIX_FOOTER = '-----END CERTIFICATE-----';

/**
 * @param {string|Uint8Array} pkix PEM or DER format
 * @return {Uint8Array} DER format
 */
export function derFromPublicKeyInfrastructure(pkix) {
  if (typeof pkix !== 'string') return pkix;
  return derFromPEM(pkix, PKIX_HEADER, PKIX_FOOTER);
}

/**
 * @param {string|Uint8Array} pkix
 * @return {string}
 */
export function pemFromPublicKeyInfrastructure(pkix) {
  return pemFromDER(derFromPublicKeyInfrastructure(pkix), PKIX_HEADER, PKIX_FOOTER);
}

/**
 * @param {import('../asn1.js').DecodedSet[]} name Sequence of names values
 */
function parseASNName(name) {
  /** @type {[string,string][]} */
  const nameEntries = [];
  for (const [nameChildType, relativeDistinguishName] of name) {
    // Only RelativeDistinguishName is supported
    if (nameChildType !== 'SET') continue;
    for (const [rdnChildType, attributeTypeAndValue] of relativeDistinguishName) {
      if (rdnChildType !== 'SEQUENCE') continue;
      const [attributeTypeTuple, attributeValueTuple] = attributeTypeAndValue;
      const [attributeTypeType, objectIdentifier] = attributeTypeTuple;
      if (attributeTypeType !== 'OBJECT_IDENTIFIER') continue;
      const [attributeValueType, value] = attributeValueTuple;

      if (attributeValueType !== 'UTF8_STRING' && attributeValueType !== 'PRINTABLE_STRING') continue;
      nameEntries.push([objectIdentifier, value]);

      // QoL values
      switch (objectIdentifier) {
        case '2.5.4.3': nameEntries.push(['commonName', value]); break;
        case '2.5.4.6': nameEntries.push(['countryName', value]); break;
        case '2.5.4.7': nameEntries.push(['localityName', value]); break;
        case '2.5.4.8': nameEntries.push(['stateOrProvinceName', value]); break;
        case '2.5.4.10': nameEntries.push(['organizationName', value]); break;
        case '2.5.4.11': nameEntries.push(['organizationalUnitName', value]); break;
        default:
      }
    }
  }
  return Object.fromEntries(nameEntries);
}

/**
 * @param {string|Uint8Array} pkix
 */
export function subjectFromPublicKeyInfrastructure(pkix) {
  const der = derFromPublicKeyInfrastructure(pkix);
  // Parsed as tuples to allow Typescript to parse type
  const [
    [certificateType, [
      tbsCertificateTuple,
      signatureAlgorithmTuple,
      signatureValueTuple,
    ]],
  ] = decodeDER(der);

  const [tbsCertificateType, tbsCertificate] = tbsCertificateTuple;
  if (certificateType !== 'SEQUENCE') throw new Error('Invalid PKIX');
  if (tbsCertificateType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [
    versionContextTuple,
    serialNumberTuple,
    signatureTuple,
    issuerTuple,
    validityTuple,
    subjectTuple,
    subjectPublicKeyInfoTuple,
    ...tbsExtras
  ] = tbsCertificate;

  const [versionContextType, versionContext] = versionContextTuple;

  if (versionContextType !== 0) throw new Error('Invalid PKIX');
  const [versionType, version] = versionContext[0];
  if (versionType !== 'INTEGER') throw new Error('Invalid PKIX');
  if (version < 3 === false) throw new Error('Unsupported PKIX Version');

  const [serialNumberType, serialNumber] = serialNumberTuple;
  if (serialNumberType !== 'INTEGER') throw new Error('Invalid PKIX');

  const [signatureType, signature] = signatureTuple;
  if (signatureType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [issuerType, issuer] = issuerTuple;
  if (issuerType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [validityType, validity] = validityTuple;
  if (validityType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [subjectType, subject] = subjectTuple;
  if (subjectType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const subjectInfo = parseASNName(subject);

  if (version >= 2) {
    for (const [extensionContextSpecificType, extensionContextSpecific] of tbsExtras) {
      if (extensionContextSpecificType !== 3) continue;
      const [extensionSequenceType, extensionSequence] = extensionContextSpecific[0];
      if (extensionSequenceType !== 'SEQUENCE') throw new Error('Invalid PKIX');
      for (const [extensionType, extensionValue] of extensionSequence) {
        if (extensionType !== 'SEQUENCE') continue;
        // Extensions

        let foundTuple;
        const [
          extnIdTuple,
          secondTuple,
          thirdTuple,
        ] = extensionValue;
        const [extnIdType, extnId] = extnIdTuple;
        if (extnIdType !== 'OBJECT_IDENTIFIER') continue;
        if (extnId !== '2.5.29.17') continue;
        const [secondType, secondValue] = secondTuple;
        let value;
        if (secondType === 'BOOLEAN') {
          if (!thirdTuple) throw new Error('Invalid PKIX');
          const [thirdType, thirdValue] = thirdTuple;
          if (thirdType !== 'OCTET_STRING') throw new Error('Invalid PKIX');
          value = thirdValue;
        } else if (secondType === 'OCTET_STRING') {
          value = secondValue;
        } else {
          throw new Error('Invalid PKIX');
        }
        const [[generalNamesType, generalNames]] = decodeDER(value);
        if (generalNamesType !== 'SEQUENCE') throw new Error('Invalid PKIX');
        const subjectAltNames = [];
        subjectInfo.subjectAltNames = subjectAltNames;
        for (const [choiceType, choiceValue] of generalNames) {
          switch (choiceType) {
            case 2:
              subjectAltNames.push(readString(choiceValue));
              break;
            default:
          }
        }
      }
      break;
    }
  }

  return subjectInfo;
}

/**
 * @param {string|Uint8Array} pkix
 */
export function validityFromPublicKeyInfrastructure(pkix) {
  const der = derFromPublicKeyInfrastructure(pkix);
  // Parsed as tuples to allow Typescript to parse type
  const [
    [certificateType, [
      tbsCertificateTuple,
      signatureAlgorithmTuple,
      signatureValueTuple,
    ]],
  ] = decodeDER(der);

  const [tbsCertificateType, tbsCertificate] = tbsCertificateTuple;
  if (certificateType !== 'SEQUENCE') throw new Error('Invalid PKIX');
  if (tbsCertificateType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [
    versionContextTuple,
    serialNumberTuple,
    signatureTuple,
    issuerTuple,
    validityTuple,
    subjectTuple,
    subjectPublicKeyInfoTuple,
    ...tbsExtras
  ] = tbsCertificate;

  const [versionContextType, versionContext] = versionContextTuple;

  if (versionContextType !== 0) throw new Error('Invalid PKIX');
  const [versionType, version] = versionContext[0];
  if (versionType !== 'INTEGER') throw new Error('Invalid PKIX');
  if (version < 3 === false) throw new Error('Unsupported PKIX Version');

  const [serialNumberType, serialNumber] = serialNumberTuple;
  if (serialNumberType !== 'INTEGER') throw new Error('Invalid PKIX');

  const [signatureType, signature] = signatureTuple;
  if (signatureType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [issuerType, issuer] = issuerTuple;
  if (issuerType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [validityType, validity] = validityTuple;
  if (validityType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [
    notBeforeTuple,
    notAfterTuple,
  ] = validity;

  const [notBeforeType, notBefore] = notBeforeTuple;
  const [notAfterType, notAfter] = notAfterTuple;
  if (notBeforeType !== 'UTC_TIME') throw new Error('Invalid PKIX');
  if (notAfterType !== 'UTC_TIME') throw new Error('Invalid PKIX');
  return { notBefore, notAfter };
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
 * Unwraps SPKI Container for internal key (RSA or EC)
 * @param {string|Uint8Array} pkix
 * @param {string} [checkOID]
 * @return {Uint8Array} DER
 */
export function publicKeyFromPublicKeyInfrastructure(pkix, checkOID) {
  const der = derFromPublicKeyInfrastructure(pkix);
  // Parsed as tuples to allow Typescript to parse type
  const [
    [certificateType, [
      tbsCertificateTuple,
      signatureAlgorithmTuple,
      signatureValueTuple,
    ]],
  ] = decodeDER(der);

  const [tbsCertificateType, tbsCertificate] = tbsCertificateTuple;
  if (certificateType !== 'SEQUENCE') throw new Error('Invalid PKIX');
  if (tbsCertificateType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [
    versionContextTuple,
    serialNumberTuple,
    signatureTuple,
    issuerTuple,
    validityTuple,
    subjectTuple,
    subjectPublicKeyInfoTuple,
    ...tbsExtras
  ] = tbsCertificate;

  const [versionContextType, versionContext] = versionContextTuple;

  if (versionContextType !== 0) throw new Error('Invalid PKIX');
  const [versionType, version] = versionContext[0];
  if (versionType !== 'INTEGER') throw new Error('Invalid PKIX');
  if (version < 3 === false) throw new Error('Unsupported PKIX Version');

  const [serialNumberType, serialNumber] = serialNumberTuple;
  if (serialNumberType !== 'INTEGER') throw new Error('Invalid PKIX');

  const [signatureType, signature] = signatureTuple;
  if (signatureType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [issuerType, issuer] = issuerTuple;
  if (issuerType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [validityType, validity] = validityTuple;
  if (validityType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [subjectType, subject] = subjectTuple;
  if (subjectType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [spkiType, spki] = subjectPublicKeyInfoTuple;
  if (spkiType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [
    spkiAlgorithmIdentifierTuple,
    spkiKeyTuple,
  ] = spki;

  const [spkiAlgorithmIdentifierType, spkiAlgorithmIdentifier] = spkiAlgorithmIdentifierTuple;
  if (spkiAlgorithmIdentifierType !== 'SEQUENCE') throw new Error('Invalid PKIX');

  const [spkiKeyType, spkiKey] = spkiKeyTuple;
  if (spkiKeyType !== 'OCTET_STRING') throw new Error('Invalid PKIX');
  if (checkOID) {
    for (const [type, value] of spkiAlgorithmIdentifier) {
      if (type === 'OBJECT_IDENTIFIER' && value === checkOID) {
        return spkiKey;
      }
    }
    return null; // Not an error, just doesn't match
  }

  return spkiKey;
}

/**
 * Returns the private key from PKCS8 if it is an EC private key
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * @param {string|Uint8Array} pkcs8
 * @return {Uint8Array}
 */
export function ecPublicKeyFromPublicKeyInfrastructure(pkcs8) {
  const publicKey = publicKeyFromPublicKeyInfrastructure(pkcs8, ASN_OID.ecPublicKey);
  if (!publicKey) {
    throw new Error('NOT AN EC PUBLIC KEY');
  }
  return publicKey;
}

/**
 * Returns the private key from PKCS8 if it is an RSA private key
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * @param {string|Uint8Array} pkcs8
 * @return {Uint8Array}
 */
export function rsaPublicKeyFromPublicKeyInfrastructure(pkcs8) {
  const publicKey = publicKeyFromPublicKeyInfrastructure(pkcs8, ASN_OID.rsaEncryption);
  if (!publicKey) {
    throw new Error('NOT AN RSA PUBLIC KEY');
  }
  return publicKey;
}

export const derFromPKIX = derFromPublicKeyInfrastructure;
export const derFromX509 = derFromPublicKeyInfrastructure;

export const pemFromPKIX = pemFromPublicKeyInfrastructure;
export const pemFromX509 = pemFromPublicKeyInfrastructure;

export const publicKeyInformationFromPKIX = publicKeyFromPublicKeyInfrastructure;
export const publicKeyInformationFromX509 = publicKeyFromPublicKeyInfrastructure;
export const spkiFromPKIX = publicKeyFromPublicKeyInfrastructure;
export const spkiFromX509 = publicKeyFromPublicKeyInfrastructure;

export const rsaPublicKeyFromPKIX = rsaPublicKeyFromPublicKeyInfrastructure;
export const rsaPublicKeyFromX509 = rsaPublicKeyFromPublicKeyInfrastructure;
export const ecPublicKeyFromPKIX = ecPublicKeyFromPublicKeyInfrastructure;
export const ecPublicKeyFromX509 = ecPublicKeyFromPublicKeyInfrastructure;
