import { decodeBase64UrlAsString, encodeBase64UrlAsString } from '../utils/base64.js';

/**
 * @param {JWSProtectedHeader|JWEProtectedHeader|string|Uint8Array|BufferSource} protectedHeader
 * @return {string}
 */
export function encodeProtectedHeader(protectedHeader) {
  if (typeof protectedHeader === 'string'
    || protectedHeader instanceof Uint8Array
    || protectedHeader instanceof ArrayBuffer
    || ArrayBuffer.isView(protectedHeader)) {
    return encodeBase64UrlAsString(protectedHeader);
  }
  return encodeBase64UrlAsString(JSON.stringify(protectedHeader));
}

/**
 * @template {JWSProtectedHeader|JWEProtectedHeader} T
 * @param {T|string|Uint8Array|BufferSource} protectedHeader
 * @return {T}
 */
export function decodeProtectedHeader(protectedHeader) {
  if (typeof protectedHeader === 'string'
    || protectedHeader instanceof Uint8Array
    || protectedHeader instanceof ArrayBuffer
    || ArrayBuffer.isView(protectedHeader)) {
    return JSON.parse(decodeBase64UrlAsString(protectedHeader));
  }
  return protectedHeader;
}
