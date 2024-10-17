/* eslint-disable no-bitwise */

import { ASN_CLASS, ASN_CONSTRUCTED, ASN_TAG } from './constants.js';

// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

const BIT_MASK_5 = 0b0001_1111;
const BIT_MASK_6 = 0b0011_1111;
const BIT_MASK_7 = 0b0111_1111;
/** Most significant bit */
const MSB_MASK = 0b1000_0000;
const BIT_MASK_8 = 0b1111_1111;

/**
 * Decode variable-length quantity
 * @param {Iterable<number>} der
 * @return {bigint[]}
 */
export function decodeVLQ(der) {
  let hasNext = false;

  let currentNumber = 0n;
  const array = [];
  for (const octet of der) {
    hasNext = (octet & MSB_MASK) === MSB_MASK;
    currentNumber <<= 7n;
    if (hasNext) {
      currentNumber |= BigInt(octet & BIT_MASK_7);
    } else {
      currentNumber |= BigInt(octet);
      array.push(currentNumber);
      currentNumber = 0n;
    }
  }
  if (hasNext) {
    throw new Error('Invalid VLQ: Unexpected termination');
  }
  return array;
}

/**
 * @param {Iterable<number>} der
 * @param {boolean} [signed]
 * @return {number|bigint}
 */
function readNumber(der, signed) {
  let bigInt = 0n;
  let isNegative = false;
  let firstByte = true;

  for (const byte of der) {
    if (signed && firstByte) {
      isNegative = (byte & MSB_MASK) !== 0;
      firstByte = false;
    }
    bigInt <<= 8n;
    bigInt |= BigInt(isNegative ? ~byte & BIT_MASK_8 : byte);
  }
  if (isNegative) {
    bigInt = ~bigInt;
  }
  if (bigInt > Number.MAX_SAFE_INTEGER || bigInt < Number.MIN_SAFE_INTEGER) return bigInt;
  return Number(bigInt);
}

/**
 * @param {Iterable<number>} der
 * @return {bigint|number}
 */
export function readUnsignedNumber(der) {
  return readNumber(der, false);
}

/**
 * @param {Iterable<number>} der
 * @return {number|bigint}
 */
export function readSignedNumber(der) {
  return readNumber(der, true);
}

/** @type {TextDecoder} */
let textDecoder;

/**
 * @param {Iterable<number>} der
 * @return {string}
 */
export function readString(der) {
  textDecoder ??= new TextDecoder();
  const buffer = (der instanceof Uint8Array ? der : Uint8Array.from(der));
  return textDecoder.decode(buffer);
}

/**
 * @param {Iterable<number>} der
 * @return {number}
 */
export function readUTCTime(der) {
  const unparsed = readString(der);
  const [
    match,
    year, month, date, hour, minute, second, tzSign, tzHour, tzMinute,
  ] = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:Z|(?:([+-]\d{2})(\d{2})))?$/.exec(unparsed);
  const yearInt = Number.parseInt(year, 10);
  const century = yearInt >= 50 ? '19' : '20';
  const isoString = `${century}${year}-${month}-${date}T${hour}:${minute}:${second ?? '00'}${tzSign ?? '+'}${tzHour ?? '00'}:${tzMinute ?? '00'}`;
  const parsed = Date.parse(isoString);
  return parsed;
}

/**
 * @param {number[]} der
 * @param {number} [offset]
 * @return {{length:number|null, bytesRead: number}}
 */
export function readLength(der, offset = 0) {
  const firstOctet = der[offset];
  if (firstOctet === 128) return { length: null, bytesRead: 1 };
  if (firstOctet < 0) throw new Error('Invalid length');
  if (firstOctet < 128) return { length: firstOctet, bytesRead: 1 };
  const size = firstOctet - 128;
  const integerOffset = offset + 1;
  const end = integerOffset + size;
  if (end > der.length) throw new Error('Invalid length');
  const data = der instanceof Uint8Array
    ? der.subarray(integerOffset, end)
    : der.slice(integerOffset, end);
  const length = readUnsignedNumber(data);
  // eslint-disable-next-line unicorn/prefer-type-error
  if (typeof length === 'bigint') { throw new Error('Invalid length'); }
  return {
    length,
    bytesRead: 1 + size,
  };
}

/**
 * Object Identifier
 * @param {number[]|Uint8Array} der
 * @return {string}
 */
export function readObjectIdentifier(der) {
  const firstByte = der[0];
  // eslint-disable-next-line unicorn/prefer-math-trunc
  const value1 = (firstByte / 40) | 0;
  const value2 = firstByte % 40;
  const rest = der instanceof Uint8Array ? der.subarray(1) : der.slice(1);
  const vlq = decodeVLQ(rest);
  const oid = [
    value1,
    value2,
    ...vlq,
  ].map((number) => number.toString(10))
    .join('.');
  return oid;
}

/**
 * @param {number[]|Uint8Array} der
 * @return {string}
 */
export function readBitString(der) {
  const orphanedBits = der[0];
  const bitLength = (der.length - 1) * 8 - orphanedBits;
  const bitString = der.slice(1).map((byte) => byte.toString(2)).join('').slice(0, bitLength);
  return bitString;
}

/** @typedef {['BOOLEAN', boolean]} DecodedBoolean */
/** @typedef {['INTEGER', number|bigint]} DecodedInteger */
/** @typedef {['BIT_STRING', string]} DecodedBitString */
/** @typedef {['PRINTABLE_STRING', string]} DecodedPrintableString */
/** @typedef {['UTF8_STRING', string]} DecodedUtf8String */
/** @typedef {['OCTET_STRING', Uint8Array]} DecodedOctetString */
/** @typedef {['OBJECT_IDENTIFIER', string]} DecodedObjectIdentifier */
/** @typedef {['UTC_TIME', number]} DecodedTime */
/** @typedef {['NULL', []]} DecodedNull */

/** @typedef {DecodedBoolean|DecodedInteger|DecodedBitString|DecodedPrintableString|DecodedUtf8String|DecodedOctetString|DecodedObjectIdentifier|DecodedNull|DecodedTime} DecodedEntry */

/** @typedef {[number, (DecodedEntry|DecodedSequence|DecodedSet|DecodedContextSpecific)|(DecodedEntry|DecodedSequence|DecodedSet|DecodedContextSpecific)[]]} DecodedContextSpecific */
/** @typedef {['SEQUENCE', (DecodedEntry|DecodedSequence|DecodedSet|DecodedContextSpecific)[]]} DecodedSequence */
/** @typedef {['SET', (DecodedEntry|DecodedSequence|DecodedSet|DecodedContextSpecific)[]]} DecodedSet */

/**
 * @param {Uint8Array} der
 * @return {(DecodedSequence|DecodedSet)[]}
 */
export function decodeDER(der) {
  const entries = [];
  let offset = 0;
  while (der.length - offset) {
    const tag = der[offset];
    offset += 1;
    const { length, bytesRead } = readLength(der, offset);
    if (length == null) throw new Error('Invalid DER: Indeterminate length is not allowed.');
    offset += bytesRead;
    const end = offset + length;
    let value = der.subarray(offset, end);

    if (tag & ASN_CONSTRUCTED) {
      value = decodeDER(value);
    }

    const type = tag & BIT_MASK_5;
    if (tag & ASN_CLASS.CONTEXT_SPECIFIC) {
      entries.push([type, value]);
    } else {
      switch (type) {
        case ASN_TAG.BOOLEAN:
          entries.push(['BOOLEAN', value[0] === 1]);
          break;
        case ASN_TAG.BIT_STRING:
          entries.push(['BIT_STRING', value]);
          break;
        case ASN_TAG.INTEGER:
          entries.push(['INTEGER', readSignedNumber(value)]);
          break;
        case ASN_TAG.PRINTABLE_STRING:
          entries.push(['PRINTABLE_STRING', readString(value)]);
          break;
        case ASN_TAG.UTF8_STRING:
          entries.push(['UTF8_STRING', readString(value)]);
          break;
        case ASN_TAG.OCTET_STRING:
          entries.push(['OCTET_STRING', value]);
          break;
        case ASN_TAG.SEQUENCE:
          entries.push(['SEQUENCE', value]);
          break;
        case ASN_TAG.SET:
          entries.push(['SET', value]);
          break;
        case ASN_TAG.OBJECT_IDENTIFIER:
          entries.push(['OBJECT_IDENTIFIER', readObjectIdentifier(value)]);
          break;
        case ASN_TAG.NULL:
          entries.push(['NULL', value.length ? value : null]);
          break;
        case ASN_TAG.UTC_TIME:
          entries.push(['UTC_TIME', readUTCTime(value)]);
          break;
        default: {
          console.warn('Unknown type', tag);
          entries.push([tag, value]);
        }
      }
    }

    offset = end;
  }
  return entries;
}
