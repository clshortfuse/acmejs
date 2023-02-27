/* eslint-disable no-bitwise */

import { decodeBase64AsArray } from '../base64.js';
import { octetFromUtf8 } from '../utf8.js';

// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

/** @enum {number} */
export const ASN_CLASS = {
  UNIVERSAL: 0b0000_0000,
  APPLICATION: 0b0100_0000,
  CONTEXT_SPECIFIC: 0b1000_0000,
  PRIVATE: 0b1100_0000,
};

export const ASN_CONSTRUCTED = 0b0010_0000;
export const ASN_PRIMITIVE = 0b0000_0000;

/** @enum {number} */
export const ASN_TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OBJECT_IDENTIFIER: 0x06,
  SEQUENCE: 0x10,
  SET: 0x11,
  PRINTABLE_STRING: 0x13,
  UTF8_STRING: 0x0C,
};

/** @enum {string} */
export const ASN_OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha1WithRSASignature: '1.2.840.113549.1.1.5',
  rsassaPSS: '1.2.840.113549.1.1.10',
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
  sha384WithRSAEncryption: '1.2.840.113549.1.1.12',
  sha512WithRSAEncryption: '1.2.840.113549.1.1.13',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaWithSHA1: '1.2.840.10045.4.1',
  ecdsaWithSHA256: '1.2.840.10045.4.3.2',
  ecdsaWithSHA384: '1.2.840.10045.4.3.3',
  ecdsaWithSHA512: '1.2.840.10045.4.3.4',
  secp192r1: '1.2.840.10045.3.1.1',
  secp224r1: '1.3.132.0.33',
  secp256r1: '1.2.840.10045.3.1.7',
  secp384r1: '1.3.132.0.34',
  secp521r1: '1.3.132.0.35',
};

const BIT_MASK_7 = 0b0111_1111;
const BIT_MASK_8 = 0b1111_1111;
const BIG_INT_BIT_MASK_8 = BigInt(BIT_MASK_8);
const BIG_INT_1 = BigInt(1);
const BIG_INT_8 = BigInt(8);
const BIG_INT_NEGATIVE_1 = BigInt(-1);

/**
 * @param {number|bigint} integer
 * @param {boolean} [signed]
 * @return {number[]}
 */
function writeNumber(integer, signed) {
  const array = [];
  let isNegative;

  // Bitshift on Number is limited to 32 signed integers

  let currentNumber = integer;
  let isBigInt = typeof integer === 'bigint';
  if (typeof integer === 'number' && (integer > 0x80_00_00_00 || integer < -0x80_00_00_00)) {
    // Cast to BigInt
    currentNumber = BigInt(integer);
    isBigInt = true;
  }

  const zero = isBigInt ? 0n : 0;
  const one = isBigInt ? BIG_INT_1 : 1;
  const eight = isBigInt ? BIG_INT_8 : 8;
  const bitMask8 = isBigInt ? BIG_INT_BIT_MASK_8 : BIT_MASK_8;
  const negativeOne = isBigInt ? BIG_INT_NEGATIVE_1 : -1;

  let byteCount = 0;
  if (currentNumber < zero) {
    isNegative = true;

    // Count number of bitshifts right until 0
    let bitsNeeded = 0;
    for (let abs = currentNumber * negativeOne; abs !== zero; abs >>= one) {
      bitsNeeded += 1;
    }

    const roundedBits = bitsNeeded + 8 - (bitsNeeded % 8);
    // const onesCompliment = ~(currentNumber * negativeOne);
    // const currentNumber = onesCompliment + one;
    byteCount = roundedBits / 8;
    // Two's compliment
  }
  do {
    const octet = currentNumber & bitMask8;
    array.unshift(isBigInt ? Number(octet) : octet);
    currentNumber >>= eight;
  } while (byteCount ? array.length !== byteCount : currentNumber > zero);

  if (currentNumber === negativeOne && !byteCount) {
    throw new Error('Unsupported unshifting!');
  }

  if (signed && !isNegative && array[0] & 0b1000_0000) {
    // Shift right an octet to not specify negative
    array.unshift(0);
  }
  return array;
}

/**
 * @param {number|bigint} integer
 * @return {number[]}
 */
export function writeUnsignedNumber(integer) {
  return writeNumber(integer);
}

/**
 * @param {number|bigint} integer
 * @return {number[]}
 */
export function writeSignedNumber(integer) {
  return writeNumber(integer, true);
}

/**
 * Encode variable-length quantity
 * @param {number} integer
 * @return {number[]}
 */
export function encodeVLQ(integer) {
  if (integer < 128) return [integer];
  const array = [integer & BIT_MASK_7];
  let currentNumber = integer >> 7;
  do {
    const value = (currentNumber & BIT_MASK_7) | 0b1000_0000;
    array.unshift(value);
    currentNumber >>= 7;
  } while (currentNumber !== 0);
  return array;
}

/**
 * @param {number|bigint} length
 * @return {number[]}
 */
export function writeLength(length) {
  if (length == null || length < 0) return [0b1000_0000];
  if (length < 128) return [Number(length)];
  const array = writeUnsignedNumber(length);
  array.unshift(0b1000_0000 + array.length);
  return array;
}

/**
 * @param {number} tag
 * @param {ArrayLike<number>&Iterable<number>} entry
 * @return {number[]}
 */
export function encodeDER(tag, entry) {
  return [tag, ...writeLength(entry.length), ...entry];
}

/**
 * @param {string} utf8String
 * @return {number[]}
 */
export function encodeUTF8String(utf8String) {
  // ASCII to Hex is the same as UTF8 to HEX (no check)
  const entry = [...octetFromUtf8(utf8String)];
  return encodeDER(ASN_TAG.UTF8_STRING, entry);
}

/**
 * @param {string} ia5String
 * @return {number[]}
 */
export function writeIA5String(ia5String) {
  // First 128 characters of ASCII (no check)
  return [...octetFromUtf8(ia5String)];
}

/**
 * @param {boolean} value
 * @return {number[]}
 */
export function encodeBoolean(value) {
  return encodeDER(ASN_TAG.BOOLEAN, [value ? 0xFF : 0x00]);
}

/**
 * @param {number|bigint} integer
 * @return {number[]}
 */
export function encodeInteger(integer) {
  const entry = writeSignedNumber(integer);
  return encodeDER(ASN_TAG.INTEGER, entry);
}

/**
 * @param {(ArrayLike<number>&Iterable<number>)[]} entries
 * @return {number[]}
 */
export function encodeSequence(...entries) {
  const entry = entries.flatMap((e) => [...e]);
  return encodeDER(ASN_CONSTRUCTED | ASN_TAG.SEQUENCE, entry);
}

/**
 * @param {(ArrayLike<number>&Iterable<number>)[]} entries
 * @return {number[]}
 */
export function encodeSet(...entries) {
  const entry = entries.flatMap((e) => [...e]);
  return encodeDER(ASN_CONSTRUCTED | ASN_TAG.SET, entry);
}

/**
 * Object Identifier
 * @param {string} identifier
 * @return {number[]}
 */
export function encodeObjectIdentifier(identifier) {
  const [value1, value2, ...rest] = identifier.split('.').map((s) => Number.parseInt(s, 10));
  const entry = [
    40 * value1 + value2,
    ...rest.flatMap((n) => encodeVLQ(n)),
  ];
  return encodeDER(ASN_TAG.OBJECT_IDENTIFIER, entry);
}

/** @return {number[]} */
export function encodeNull() {
  return encodeDER(ASN_TAG.NULL, []);
}

/**
 * @param {ArrayLike<number>&Iterable<number>} entry
 * @return {number[]}
 */
export function encodeOctetString(entry) {
  return encodeDER(ASN_TAG.OCTET_STRING, entry);
}

/**
 * https://www.rfc-editor.org/rfc/rfc4055#section-2.1
 * @param {string} oid
 * @param {number[]|string|null} [params] DER or OID
 * @return {number[]}
 */
export function encodeAlgorithmIdentifer(oid, params) {
  return encodeSequence(
    encodeObjectIdentifier(oid),
    typeof params === 'string'
      ? encodeObjectIdentifier(oid)
      : params ?? encodeNull(), // Supposed to optional, but made mandatory for RSA compatibility
  );
}

/**
 * @see https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
 * @param {string} type Object Identifier
 * @param {number[]} value
 * @return {number[]}
 */
export function encodeAttribute(type, value) {
  return encodeSequence(
    encodeObjectIdentifier(type),
    encodeSet(value),
  );
}

/**
 * @see https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
 * @param {string} id Object Identifier
 * @param {number[]} value
 * @param {boolean} [critical=false]
 * @return {number[]}
 */
export function encodeExtension(id, value, critical) {
  return encodeSequence(
    encodeObjectIdentifier(id),
    critical ? encodeBoolean(true) : [],
    encodeOctetString(value),
  );
}

/**
 * @param {string} dnsName
 * @return {number[]}
 */
export function encodeDNSName(dnsName) {
  const dNSNameTag = 2;
  return encodeDER(ASN_CLASS.CONTEXT_SPECIFIC | dNSNameTag, writeIA5String(dnsName));
}

/**
 * @param {ArrayLike<number>&Iterable<number>} data
 * @param {number} [length]
 * @return {number[]}
 */
export function encodeBitString(data, length = data.length * 8) {
  const extraBits = data.length === length ? 0 : length % 8;
  const orphanedBits = (extraBits === 0) ? 0 : 8 - extraBits;
  return encodeDER(ASN_TAG.BIT_STRING, [
    orphanedBits,
    ...data,
  ]);
}

/**
 * @param {string} printableString
 * @return {number[]}
 */
export function encodePrintableString(printableString) {
  // ASCII to Hex is the same as UTF8 to HEX
  // No checks here
  const entry = [...octetFromUtf8(printableString)];
  return encodeDER(ASN_TAG.PRINTABLE_STRING, entry);
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc3447.html (RSASSA-PSS)
 * @see https://datatracker.ietf.org/doc/html/rfc5754 (SHA2)
 * @param {JWK} jwk
 * @return {number[]}
 */
export function parseSignatureAlgorithm(jwk) {
  if (jwk.alg.startsWith('PS')) {
    const keySize = jwk.n ? decodeBase64AsArray(jwk.n).length * 8 : 2048;
    let hashOID;
    let bits;
    switch (jwk.alg) {
      case 'PS256': {
        hashOID = ASN_OID.sha256;
        bits = 256;
        break;
      }
      case 'PS384': {
        hashOID = ASN_OID.sha384;
        bits = 384;
        break;
      }
      case 'PS512': {
        hashOID = ASN_OID.sha512;
        bits = 512;
        break;
      }
      default: throw new Error('Unknown algorithm');
    }
    return encodeAlgorithmIdentifer(
      ASN_OID.rsassaPSS,
      encodeSequence(
        encodeAlgorithmIdentifer(hashOID), // hashAlgorithm
        encodeNull(), // maskGenAlgorithm
        encodeInteger(Math.ceil((keySize - 1) / 8) - (bits / 8) - 2), // saltLength
        encodeNull(), // trailerField
      ),
    );
  }

  switch (jwk.alg) {
    case 'HS256':
      return encodeAlgorithmIdentifer(ASN_OID.sha256);
    case 'HS384':
      return encodeAlgorithmIdentifer(ASN_OID.sha384);
    case 'HS512':
      return encodeAlgorithmIdentifer(ASN_OID.sha512);
    case 'RS256':
      return encodeAlgorithmIdentifer(ASN_OID.sha256WithRSAEncryption);
    case 'RS384':
      return encodeAlgorithmIdentifer(ASN_OID.sha384WithRSAEncryption);
    case 'RS512':
      return encodeAlgorithmIdentifer(ASN_OID.sha512WithRSAEncryption);
    case 'ES256':
      return encodeAlgorithmIdentifer(ASN_OID.ecdsaWithSHA256);
    case 'ES384':
      return encodeAlgorithmIdentifer(ASN_OID.ecdsaWithSHA384);
    case 'ES512':
      return encodeAlgorithmIdentifer(ASN_OID.ecdsaWithSHA512);
    default:
  }
  throw new Error('Unknown `alg` value.');
}

/** @alias */
export const encodeExtensions = encodeSequence;
/** @alias */
export const encodeGeneralNames = encodeSequence;
/** @alias */
export const encodeSubjectAltNameValue = encodeGeneralNames;
