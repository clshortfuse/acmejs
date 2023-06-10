/* eslint-disable no-bitwise */
// https://datatracker.ietf.org/doc/html/rfc4648#section-4

import { octetFromUtf8 } from './utf8.js';

const BASE64_CHAR_62 = '+';
const BASE64_CHAR_63 = '/';
const BASE64_CHAR_PAD = '=';
const BASE64_CODEPOINT_62 = BASE64_CHAR_62.codePointAt(0);
const BASE64_CODEPOINT_63 = BASE64_CHAR_63.codePointAt(0);
const BASE64_CODEPOINT_PAD = BASE64_CHAR_PAD.codePointAt(0);

const BASE64URL_CHAR_62 = '-';
const BASE64URL_CHAR_63 = '_';
const BASE64URL_CHAR_PAD = ''; // Optional

const BASE64URL_CODEPOINT_62 = BASE64URL_CHAR_62.codePointAt(0);
const BASE64URL_CODEPOINT_63 = BASE64URL_CHAR_63.codePointAt(0);

const BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64URL_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const BASE64_CHAR_TO_SEXTET_INDEX = new Map(Array.from(BASE64_TABLE).map((c, index) => [c, index]));
const BASE64_CODEPOINT_TO_SEXTET_INDEX = new Map(Array.from(BASE64_TABLE).map((c, index) => [c.codePointAt(0), index]));
const BASE64_SEXTET_TO_CHAR_INDEX = new Map(Array.from(BASE64_TABLE).map((c, index) => [index, c]));
const BASE64_SEXTET_TO_CODEPOINT_INDEX = new Map(Array.from(BASE64_TABLE).map((c, index) => [index, c.codePointAt(0)]));

/** @type {Map<number,number>} */
const BIT_MASKS = new Map([1, 2, 3, 4, 5, 6, 7, 8].map((v) => [v, 2 ** v - 1]));

const BIT_MASK_1 = BIT_MASKS.get(1);
const BIT_MASK_2 = BIT_MASKS.get(2);
const BIT_MASK_3 = BIT_MASKS.get(3);
const BIT_MASK_4 = BIT_MASKS.get(4);
const BIT_MASK_5 = BIT_MASKS.get(5);
const BIT_MASK_6 = BIT_MASKS.get(6);
const BIT_MASK_7 = BIT_MASKS.get(7);
const BIT_MASK_8 = BIT_MASKS.get(8);

/**
 * @param {string|BufferSource} source
 * @return {Iterable<number>}
 */
function toIterableUint8(source) {
  if (typeof source === 'string') {
    return octetFromUtf8(source);
  }
  if (source instanceof Uint8Array) {
    return source;
  }
  if (source instanceof ArrayBuffer) {
    return new Uint8Array(source);
  }
  return new Uint8Array(source.buffer);
}

/**
 * @param {number} sextet
 * @param {boolean} [url=false]
 * @return {number}
 */
function base64CodepointFromSextet(sextet, url) {
  if (url) {
    if (sextet === 63) return BASE64URL_CODEPOINT_63;
    if (sextet === 62) return BASE64URL_CODEPOINT_62;
  }
  const value = BASE64_SEXTET_TO_CODEPOINT_INDEX.get(sextet);
  if (value === null) throw new Error(`Invalid value: ${sextet}`);
  return value;
}

/**
 * @param {number} codepoint
 * @param {boolean} [url=false]
 * @return {number}
 */
function sextetFromBase64Codepoint(codepoint, url) {
  if (url) {
    if (codepoint === BASE64URL_CODEPOINT_62) return 62;
    if (codepoint === BASE64URL_CODEPOINT_63) return 63;
  }
  const value = BASE64_CODEPOINT_TO_SEXTET_INDEX.get(codepoint);
  if (value === null) throw new Error(`Invalid value: ${codepoint}`);
  return value;
}

/**
 * @param {number} sextet
 * @param {boolean} [url=false]
 * @return {string}
 */
function base64CharFromSextet(sextet, url) {
  if (url) {
    if (sextet === 62) return BASE64URL_CHAR_62;
    if (sextet === 63) return BASE64URL_CHAR_63;
  }
  const value = BASE64_SEXTET_TO_CHAR_INDEX.get(sextet);
  if (value == null) throw new Error(`Invalid value: ${sextet}`);
  return value;
}

/**
 * @param {string} char
 * @param {boolean} [url=false]
 * @return {number} sextet
 */
function sextetFromBase64Char(char, url) {
  if (url) {
    if (char === BASE64URL_CHAR_62) return 62;
    if (char === BASE64URL_CHAR_63) return 63;
  }
  const value = BASE64_CHAR_TO_SEXTET_INDEX.get(char);
  if (value == null) throw new Error(`Invalid value: ${char}`);
  return value;
}

/**
 * @param {Iterable<number>} source
 * @yields {number} sextet
 */
function* sextetsFromOctets(source) {
  let storedBits = 0;
  let bitStore = 0;
  for (const octet of source) {
    const bitsNeeded = 6 - storedBits;
    const partial = octet >> (8 - bitsNeeded);
    const sextet = bitStore | partial;

    yield sextet;

    const remainingBits = 8 - bitsNeeded;

    const mask = BIT_MASKS.get(remainingBits) ?? (2 ** remainingBits - 1);
    const remainder = octet & mask;

    bitStore = remainder << (6 - remainingBits);
    storedBits = remainingBits;
    if (storedBits === 6) {
      yield bitStore;
      bitStore = 0;
      storedBits = 0;
    }
  }
  if (storedBits) {
    yield bitStore;
  }
}

/**
 * @param {string|BufferSource} source
 * @param  {boolean} [url=false]
 * @return {string}
 */
export function encodeBase64AsString(source, url) {
  const iterableSource = toIterableUint8(source);
  let result = '';

  let count = 0;
  for (const sextet of sextetsFromOctets(iterableSource)) {
    count++;
    result += base64CharFromSextet(sextet, url);
  }
  if (!url) {
    switch (count % 4) {
      case 3:
        return `${result}=`;
      case 2:
        return `${result}==`;
      default:
    }
  }
  return result;
}

/**
 * Strips any non Base64 characters
 * @param {string} source
 * @param  {boolean} [url=false]
 * @return {string}
 */
export function cleanBase64String(source, url) {
  let result = '';

  let count = 0;
  const table = url ? BASE64URL_TABLE : BASE64_TABLE;
  for (const char of source) {
    if (table.includes(char)) {
      count++;
      result += char;
    }
  }
  if (!url) {
    switch (count % 4) {
      case 3:
        return `${result}=`;
      case 2:
        return `${result}==`;
      default:
    }
  }
  return result;
}

/**
 * @param {string|Uint8Array|BufferSource} source
 * @param  {boolean} [url=false]
 * @return {Uint8Array}
 */
export function encodeBase64AsArray(source, url) {
  // Every 24bits is 4 (characters) of data

  // Javascript underreports 3byte utf8 as single length, therefore byte count could be upto 3x utf8 length
  // TODO: Implement optimistic size prediction

  const iterableSource = toIterableUint8(source);
  const destinationSize = (typeof source === 'string') ? (source.length * 4)
    : Math.ceil((/** @type {Uint8Array} */ (iterableSource).length * 8) / 6);

  const padSize = 4 - (destinationSize % 4);
  const array = new Uint8Array(destinationSize + padSize);

  let count = 0;
  for (const sextet of sextetsFromOctets(iterableSource)) {
    array[count++] = base64CodepointFromSextet(sextet, url);
  }
  if (!url) {
    switch (count % 4) {
      case 2:
        array[count++] = BASE64_CODEPOINT_PAD;
        // Fallthrough
      case 3:
        array[count++] = BASE64_CODEPOINT_PAD;
        break;
      default:
    }
  }
  // Maintains memory footprint, but faster than slice
  return array.subarray(0, count);
}

/**
 * @param {string|Uint8Array} source
 * @param  {?boolean} [url] Explicit base64url processing (auto if omitted)
 * @return {Uint8Array}
 */
export function decodeBase64AsArray(source, url) {
  // Base64 has 24bits of data for every 32bits

  let sourceBits = source.length * 6;
  const unalignedBytes = source.length % 4;
  if (unalignedBytes) {
    if (url === false) throw new Error(`Invalid Base64 source: ${source.toString()}`);
    switch (unalignedBytes) {
      case 2:
        sourceBits += 6;
        // Fallthrough
      case 3:
        sourceBits += 6;
        break;
      default:
      case 1:
        throw new Error(`Invalid Base64 source: ${source.toString()}`);
    }
  }
  const destinationSize = (url === false) ? sourceBits / 8 : Math.ceil(sourceBits / 8);
  const array = new Uint8Array(destinationSize);

  const isString = typeof source === 'string';
  const decoder = isString ? sextetFromBase64Char : sextetFromBase64Codepoint;
  const decodeURL = (url !== false);

  let tripleByte = 0b0000_0000_0000_0000_0000_0000;
  let writePosition = 0;
  for (let i = 0; i < source.length; i++) {
    const offset = i % 4;
    const value = source[i];
    const isPadding = isString
      ? value === BASE64_CHAR_PAD
      : value === BASE64_CODEPOINT_PAD;
    if (!isPadding) {
      const sextet = decoder(value, decodeURL);
      const shiftedData = sextet << (6 * (3 - offset));
      tripleByte |= shiftedData;
    }

    let bytesToWrite = 0;
    if (isPadding) {
      bytesToWrite = offset - 1;
    } else if ((offset === 3) || (i === source.length - 1)) {
      bytesToWrite = offset;
    }
    if (bytesToWrite) {
      for (let j = 0; j < bytesToWrite; j++) {
        const maskedValue = (tripleByte >> (8 * (2 - j))) & BIT_MASK_8;
        array[writePosition++] = maskedValue;
      }
      tripleByte = 0;
    }

    if (isPadding) break;
  }

  if (array.length === writePosition) return array;
  return array.subarray(0, writePosition);
}

/**
 * @param {string|Uint8Array} source
 * @param  {?boolean} [url] Explicit base64url processing (auto if omitted)
 * @return {string}
 */
export function decodeBase64AsASCII(source, url) {
  // Base64 has 24bits of data for every 32bits

  const decodeURL = (url !== false);
  let output = '';
  const isString = typeof source === 'string';
  const decoder = isString ? sextetFromBase64Char : sextetFromBase64Codepoint;

  let tripleByte = 0b0000_0000_0000_0000_0000_0000;
  for (let i = 0; i < source.length; i++) {
    const offset = i % 4;
    const value = source[i];
    const isPadding = isString ? value === BASE64_CHAR_PAD : value === BASE64_CODEPOINT_PAD;
    if (!isPadding) {
      const sextet = decoder(value, decodeURL);
      const shiftedData = sextet << (6 * (3 - offset));
      tripleByte |= shiftedData;
    }

    let bytesToWrite = 0;
    if (isPadding) {
      bytesToWrite = offset - 1;
    } else if ((offset === 3) || (i === source.length - 1)) {
      bytesToWrite = offset;
    }
    if (bytesToWrite) {
      for (let j = 0; j < bytesToWrite; j++) {
        const charCode = (tripleByte >> (8 * (2 - j))) & BIT_MASK_8;
        // eslint-disable-next-line unicorn/prefer-code-point
        output += String.fromCharCode(charCode);
      }
      tripleByte = 0;
    }

    if (isPadding) break;
  }

  return output;
}

/**
 * @param {string|Uint8Array|BufferSource} source
 * @param  {?boolean} [url] Explicit base64url processing (auto if omitted)
 * @return {string}
 */
export function decodeBase64AsUtf8(source, url) {
  // Base64 has 24bits of data for every 32bits

  const decodeURL = (url !== false);
  let output = '';
  const isString = typeof source === 'string';
  const decoder = isString ? sextetFromBase64Char : sextetFromBase64Codepoint;

  let tripleByte = 0b0000_0000_0000_0000_0000_0000;
  let codePoint = 0;
  let codePointLength = 0;
  let codePointIndex = 0;
  for (let i = 0; i < source.length; i++) {
    const offset = i % 4;
    const value = source[i];
    const isPadding = isString ? value === BASE64_CHAR_PAD : value === BASE64_CODEPOINT_PAD;
    if (!isPadding) {
      const sextet = decoder(value, decodeURL);
      const shiftedData = sextet << (6 * (3 - offset));
      tripleByte |= shiftedData;
    }

    let bytesToWrite = 0;
    if (isPadding) {
      bytesToWrite = offset - 1;
    } else if ((offset === 3) || (i === source.length - 1)) {
      bytesToWrite = offset;
    }
    if (bytesToWrite) {
      for (let j = 0; j < bytesToWrite; j++) {
        const codePointOctet = (tripleByte >> (8 * (2 - j))) & BIT_MASK_8;
        if (!codePointLength) {
          if (codePointOctet >> 7 === 0) {
            codePointLength = 1;
            codePoint = codePointOctet;
          } else if (codePointOctet >> 5 === 0b110) {
            codePointLength = 2;
            codePoint = codePointOctet & BIT_MASK_5;
          } else if (codePointOctet >> 4 === 0b1110) {
            codePointLength = 3;
            codePoint = codePointOctet & BIT_MASK_4;
          } else if (codePointOctet >> 3 === 0b1_1110) {
            codePointLength = 4;
            codePoint = codePointOctet & BIT_MASK_3;
          } else {
            throw new Error('Invalid source data');
          }
        }
        if (codePointIndex) {
          if (codePointOctet >> 6 !== 0b10) throw new Error('Invalid source data');
          // Shift 6 and mask
          codePoint <<= 6;
          codePoint |= (codePointOctet & BIT_MASK_6);
        }
        codePointIndex++;
        if (codePointIndex === codePointLength) {
          output += String.fromCodePoint(codePoint);
          codePointIndex = 0;
          codePointLength = 0;
        }
      }
      tripleByte = 0;
    }

    if (isPadding) break;
  }
  if (codePointLength) {
    output += String.fromCodePoint(codePoint);
  }

  return output;
}

/** @alias encodeBase64AsString */
export const encodeBase64AsASCII = encodeBase64AsString;
/** @alias encodeBase64AsString */
export const encodeBase64AsUtf8 = encodeBase64AsString;

/** @alias decodeBase64AsUtf8 */
export const decodeBase64AsString = decodeBase64AsUtf8;

export const encodeBase64UrlAsArray = (source) => encodeBase64AsArray(source, true);
export const encodeBase64UrlAsString = (source) => encodeBase64AsString(source, true);

export const decodeBase64UrlAsArray = (source) => decodeBase64AsArray(source, true);

export const decodeBase64UrlAsString = (source) => decodeBase64AsString(source, true);
export const decodeBase64UrlAsUtf8 = (source) => decodeBase64AsUtf8(source, true);
export const decodeBase64UrlAsASCII = (source) => decodeBase64AsASCII(source, true);

export const cleanBase64UrlString = (source) => cleanBase64String(source, true);
