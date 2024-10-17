import { encodeBase64AsString } from '../utils/base64.js';

/**
 * @param {string} username
 * @param {string} password
 * @return {string}
 */
export function buildAuthorizationHeader(username, password) {
  return `Basic ${encodeBase64AsString(`${username}:${password}`)}`;
}

/**
 * @param {RequestInit['headers']} headers
 * @param {string} hostname
 * @param {string} token
 * @param {string} authorization
 * @return {Promise<any>}
 */
export async function putHTTPResource(headers, hostname, token, authorization) {
  try {
    const putResponse = await fetch(`http://${hostname}/.well-known/acme-challenge/${token}`, {
      method: 'PUT',
      headers,
      body: authorization,
    });
    if (putResponse.ok) return;
    throw new Error(putResponse.statusText);
  } catch (e) {
    console.error(e);
  }
}

/**
 * @param {Object} [options]
 * @param {string} [options.username]
 * @param {string} [options.password]
 * @param {string} [options.token]
 * @param {string} [options.cookie]
 * @return {EventTarget}
 */
export function buildEventTarget({ username, password, token, cookie = 'token' } = {}) {
  const eventTarget = new EventTarget();
  /** @type {RequestInit['headers']} */
  const headers = {};
  if (username && password) {
    headers.Authorization = buildAuthorizationHeader(username, password);
  }
  if (token) {
    headers.Cookie = `${cookie}=${token}`;
  }
  eventTarget.addEventListener('httpresourceneeded', (event) => {
    const { name, value, domain } = event.detail;

    event.waitUntil(putHTTPResource(
      headers,
      domain,
      name,
      value,
    ));
  });
  return eventTarget;
}
