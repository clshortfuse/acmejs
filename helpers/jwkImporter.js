import { ASN_OID, decodeDER } from '../utils/asn1.js';
import { derFromPrivateKeyInformation } from '../utils/certificate.js';

/**
 * Automatically suggest an importKey algorithm
 * @see https://datatracker.ietf.org/doc/html/rfc5208#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc2313#section-11
 * @param {string|Uint8Array} privateKeyInformation pkcs8
 * @return {Parameters<SubtleCrypto['importKey']>[2]}
 */
export function suggestImportKeyAlgorithm(privateKeyInformation) {
  const der = derFromPrivateKeyInformation(privateKeyInformation);
  const [
    [privateKeyInfoType, [
      [versionType, version],
      algorithmIdentifierSequence,
      [privateKeyType, privateKey], // Skip validation
    ]],
  ] = decodeDER(der);
  if (privateKeyInfoType !== 'SEQUENCE') throw new Error('Invalid Private Key Information');
  if (versionType !== 'INTEGER') throw new Error('Invalid Private Key Information');
  if (version !== 0) throw new Error('Unsupported Private Key Information Version');
  const [algorithmIdentifierSequenceType, algorithmIdentifierSequenceValues] = algorithmIdentifierSequence;
  if (algorithmIdentifierSequenceType !== 'SEQUENCE') throw new Error('Invalid Private Key Information');

  /** @type {Set<string>} */
  const objectIdentifiers = new Set();
  for (const [type, value] of algorithmIdentifierSequenceValues) {
    if (type === 'OBJECT_IDENTIFIER') {
      objectIdentifiers.add(value);
    }
  }

  if (objectIdentifiers.has(ASN_OID.rsaEncryption)) {
    return {
      name: 'RSASSA-PKCS1-v1_5', // RSA-PSS isn't supported by LetsEncrypt
      hash: { name: 'SHA-256' },
    };
  }
  if (objectIdentifiers.has(ASN_OID.ecPublicKey)) {
    if (objectIdentifiers.has(ASN_OID.secp256r1)) {
      return {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: { name: 'SHA-256' },
      };
    }
    if (objectIdentifiers.has(ASN_OID.secp384r1)) {
      return {
        name: 'ECDSA',
        namedCurve: 'P-384',
        hash: { name: 'SHA-384' },
      };
    }
    if (objectIdentifiers.has(ASN_OID.secp521r1)) {
      return {
        name: 'ECDSA',
        namedCurve: 'P-521',
        hash: { name: 'SHA-512' },
      };
    }
  }

  return null;
}
