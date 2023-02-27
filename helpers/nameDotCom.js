import { encodeBase64AsString } from '../utils/base64.js';

const NAME_DOT_COM_HOST = 'https://api.name.com';

/**
 * @param {string} username
 * @param {string} password
 * @return {string}
 */
export function buildAuthorizationHeader(username, password) {
  return `Basic ${encodeBase64AsString(`${username}:${password}`)}`;
}

/**
 * @param {string} authorization
 * @param {string} domainName
 * @return {Promise<number>} Records cleared
 */
export async function clearDNSRecords(authorization, domainName) {
  const recordsResponse = await fetch(`${NAME_DOT_COM_HOST}/v4/domains/${domainName}/records`, {
    method: 'GET',
    headers: {
      Authorization: authorization,
    },
  });
  const list = await recordsResponse.json();
  const records = list.records ?? [];
  const promises = [];
  for (const record of records) {
    if (record.type !== 'TXT') continue;
    if (record.host !== '_acme-challenge') continue;
    const promise = fetch(`${NAME_DOT_COM_HOST}/v4/domains/${domainName}/records/${record.id}`, {
      method: 'DELETE',
      headers: {
        Authorization: authorization,
      },
    });
    promises.push(promise);
  }
  if (!promises.length) return 0;
  await Promise.all(promises);
  return promises.length;
}

/**
 * @param {string} authorization
 * @param {string} domainName
 * @param {string} txt
 * @return {Promise<any>}
 */
export async function addDnsRecord(authorization, domainName, txt) {
  const recordsResponse = await fetch(`${NAME_DOT_COM_HOST}/v4/domains/${domainName}/records`, {
    method: 'GET',
    headers: {
      Authorization: authorization,
    },
  });
  const list = await recordsResponse.json();
  const records = list.records ?? [];
  for (const record of records) {
    if (record.type !== 'TXT') continue;
    if (record.host !== '_acme-challenge') continue;
    if (record.answer !== txt) continue;
    return;
  }

  const data = {
    domainName,
    host: '_acme-challenge',
    type: 'TXT',
    answer: txt,
  };
  const postRequest = await fetch(`${NAME_DOT_COM_HOST}/v4/domains/${domainName}/records`, {
    method: 'POST',
    headers: {
      Authorization: authorization,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });
  if (postRequest.ok) return;
  throw new Error(postRequest.statusText);
}

/**
 * @param {string} username
 * @param {string} token
 * @return {EventTarget}
 */
export function buildEventTarget(username, token) {
  const eventTarget = new EventTarget();

  eventTarget.addEventListener('dnsrecordneeded', (event) => {
    const { name, value, domain } = event.detail;
    const authorization = buildAuthorizationHeader(username, token);

    event.waitUntil(addDnsRecord(authorization, domain, value));
  });
  return eventTarget;
}
