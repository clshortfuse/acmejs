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
  ecdsaWithSHA256: '1.2.840.10045.4.3.2',
  ecdsaWithSHA384: '1.2.840.10045.4.3.3',
  ecdsaWithSHA512: '1.2.840.10045.4.3.4',
};

const BIT_MASK_7 = 0b0111_1111;
const BIT_MASK_8 = 0b1111_1111;
const BIG_INT_BIT_MASK_8 = BigInt(BIT_MASK_8);
const BIG_INT_1 = BigInt(1);
const BIG_INT_8 = BigInt(8);
const BIG_INT_NEGATIVE_1 = BigInt(-1);

