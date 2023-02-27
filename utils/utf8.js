/* eslint-disable no-bitwise */

const BIT_MASK_6 = 0b11_1111;
const BIT_MASK_8 = 0b1111_1111;

const CODEPOINT_SINGLE_LIMIT = 0x00_80;
const CODEPOINT_DOUBLE_LIMIT = 0x08_00;
const CODEPOINT_TRIPLE_LIMIT = 0x1_00_00;
const CODEPOINT_QUAD_LIMIT = 0x11_00_00;
const CODEPOINT_EXTRA_BYTE = 0b10 << 6;

/**
 * @param {string} utf8
 * @yields {number} octet
 * @return {Generator<number>}
 */
export function* octetFromUtf8(utf8) {
  for (let i = 0; i < utf8.length; i++) {
    const codePoint = utf8.codePointAt(i);
    let charBytes = 0;
    if (codePoint < CODEPOINT_SINGLE_LIMIT) {
      yield (codePoint);
      continue;
    }
    if (codePoint < CODEPOINT_DOUBLE_LIMIT) {
      charBytes = 2;
    } else if (codePoint < CODEPOINT_TRIPLE_LIMIT) {
      charBytes = 3;
    } else if (codePoint < CODEPOINT_QUAD_LIMIT) {
      charBytes = 4;
      i++;
    }

    // First byte is has `charBytes` amount of leading 1 bits
    const firstByteValue = (0b1111_1111 << (8 - charBytes)) & BIT_MASK_8;
    for (let j = 0; j < charBytes; j++) {
      const position = 6 * (charBytes - 1 - j);
      // Push target into last 6 bits and mask
      const sextet = (codePoint >> position) & BIT_MASK_6;
      const initalValue = j === 0 ? firstByteValue : CODEPOINT_EXTRA_BYTE;
      const octet = initalValue | sextet;
      yield octet;
    }
  }
}
