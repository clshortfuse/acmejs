import { decodeBase64AsArray, encodeBase64AsString } from '../base64.js';

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
    } else if (splits.length >= 5) {
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

/**
 * Reconstructs PEM with line breaks and 64 char limit
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
