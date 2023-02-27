/* eslint-disable no-bitwise */

import { ASN_CONSTRUCTED, ASN_TAG } from './constants.js';

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

/**
 * @param {number[]} der
 * @param {number} [offset=0]
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

/** @typedef {['BOOLEAN', boolean]} DecodedBoolean */
/** @typedef {['INTEGER', number|bigint]} DecodedInteger */
/** @typedef {['UTF8_STRING', string]} DecodedUtf8String */
/** @typedef {['OCTET_STRING', Uint8Array]} DecodedOctetString */
/** @typedef {['OBJECT_IDENTIFIER', string]} DecodedObjectIdentifier */
/** @typedef {['NULL', []]} DecodedNull */

/** @typedef {DecodedBoolean|DecodedInteger|DecodedUtf8String|DecodedOctetString|DecodedObjectIdentifier|DecodedNull} DecodedEntry */

/** @typedef {['SEQUENCE', (DecodedEntry|DecodedSequence|DecodedSet)[]]} DecodedSequence */
/** @typedef {['SET', (DecodedEntry|DecodedSequence|DecodedSet)[]]} DecodedSet */

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
    switch (type) {
      case ASN_TAG.BOOLEAN:
        entries.push(['BOOLEAN', value[0] === 1]);
        break;
      case ASN_TAG.INTEGER:
        entries.push(['INTEGER', readSignedNumber(value)]);
        break;
      case ASN_TAG.UTF8_STRING:
        entries.push(['UTF8_STRING', new TextDecoder().decode(value)]);
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
      default: {
        console.warn('Unknown type', tag);
        entries.push([tag, value]);
      }
    }

    offset = end;
  }
  return entries;
}
