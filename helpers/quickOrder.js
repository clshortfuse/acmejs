/* eslint-disable no-await-in-loop */
import ACMEAgent from '../lib/ACMEAgent.js';
import { encodeBase64UrlAsString } from '../utils/base64.js';
import { createCSR, derFromPrivateKeyInformation, jwkFromPrivateKeyInformation } from '../utils/certificate.js';
import { checkDnsTxt } from '../utils/dns.js';
import { dispatchEvent, dispatchExtendableEvent } from '../utils/events.js';

import { suggestImportKeyAlgorithm } from './jwkImporter.js';

const LETS_ENCRYPT_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory';

/**
 * @param {Object} options
 * @param {ACMEAgent} options.agent
 * @param {string[]} options.urls
 * @param {EventTarget} [options.eventTarget] used for async callbacks
 * @return {Promise<any>} return when ready
 */
export async function processAuthorizations({ agent, urls, eventTarget }) {
  const authorizations = await agent.fetchAuthorizations(urls);
  const challegesToValidate = [];
  const completedChallenges = [];
  const processingChallenges = [];
  for (const authz of authorizations) {
    for (const challenge of authz.challenges) {
      switch (challenge.status) {
        case 'valid':
          completedChallenges.push(challenge);
          continue;
        case 'invalid':
          throw new Error('Invalid challenge!');
        case 'processing':
          processingChallenges.push(challenge);
          continue;
        case 'pending':
          break;
        default:
          throw new Error(`Unknown challenge status: ${challenge.status}`);
      }
      if (challenge.type !== 'dns-01') continue;
      const recordName = '_acme-challenge';
      const recordValue = await agent.buildKeyAuthorization(challenge);
      if (eventTarget) {
        await dispatchExtendableEvent(eventTarget, 'dnsrecordneeded', {
          name: recordName,
          value: recordValue,
          domain: authz.identifier.value,
        });
      }
      if (await checkDnsTxt(`_acme-challenge.${authz.identifier.value}`, recordValue)) {
        if (eventTarget) {
          await dispatchExtendableEvent(eventTarget, 'challengeverified', challenge);
        }
        challegesToValidate.push(challenge);
      }
    }
  }
  for (const challenge of challegesToValidate) {
    await agent.validateChallenge(challenge);
  }
  if (challegesToValidate.length || processingChallenges.length) {
    // Validations were performed. Waiting for 5 seconds and checking order status
    await new Promise((resolve) => setTimeout(resolve, 5000));
    await processAuthorizations({ agent, urls, eventTarget });
    return;
  }
  if (!completedChallenges.length) {
    throw new Error('No challenges?');
  }
}

/**
 * @param {Object} options
 * @param {ACMEAgent} options.agent
 * @param {Order} options.order
 * @param {EventTarget} [options.eventTarget] used for async callbacks
 * @return {Promise<any>} return when ready
 */
export async function authorizeOrder({ order, agent, eventTarget }) {
  if (order.status === 'ready' || order.status === 'valid') return;
  if (order.status !== 'pending') {
    throw new Error('Order not processable yet.');
  }
  await processAuthorizations({
    agent,
    urls: order.authorizations,
    eventTarget,
  });
}

/**
 * @param {Object} options
 * @param {boolean} options.tosAgreed
 * @param {string} options.email
 * @param {JWK|string|Uint8Array} options.jwk Account JWK or PrivateKeyInformation (PKCS8)
 * @param {string} options.domain
 * @param {string} [options.orderUrl] existing order URL (blank for new)
 * @param {string} [options.directoryUrl] defaults to LetsEncrypt Production
 * @param {EventTarget} [options.eventTarget] used for async callbacks
 * @param {Object} options.csr
 * @param {string} [options.csr.organizationName]
 * @param {string} [options.csr.organizationalUnitName]
 * @param {string} [options.csr.localityName]
 * @param {string} [options.csr.stateOrProvinceName]
 * @param {string} [options.csr.countryName]
 * @param {JWK|string|Uint8Array} options.csr.jwk CSR JWK or PrivateKeyInformation (PKCS8)
 * @return {Promise<any>}
 */
export async function getWildcardCertificate(options) {
  /** @type {JWK} */
  let accountJWK;
  /** @type {JWK} */
  let csrJWK;

  if (typeof options.jwk === 'string' || options.jwk instanceof Uint8Array) {
    const der = derFromPrivateKeyInformation(options.jwk);
    accountJWK = await jwkFromPrivateKeyInformation(der, suggestImportKeyAlgorithm(der));
  } else {
    accountJWK = options.jwk;
  }

  if (typeof options.csr.jwk === 'string' || options.csr.jwk instanceof Uint8Array) {
    const der = derFromPrivateKeyInformation(options.csr.jwk);
    csrJWK = await jwkFromPrivateKeyInformation(der, suggestImportKeyAlgorithm(der));
  } else {
    csrJWK = options.csr.jwk;
  }

  const agent = new ACMEAgent({
    directoryUrl: options.directoryUrl || LETS_ENCRYPT_DIRECTORY_URL,
    jwk: accountJWK,
  });
  await agent.fetchDirectory();
  const account = await agent.createAccount({
    termsOfServiceAgreed: options.tosAgreed,
    contact: [`mailto:${options.email}`],
  });
  if (options.eventTarget) {
    dispatchEvent(options.eventTarget, 'account', account);
    dispatchEvent(options.eventTarget, 'accountUrl', agent.accountUrl);
  }
  let order;
  if (options.orderUrl) {
    order = await agent.fetchOrder(options.orderUrl);
  } else {
    order = await agent.createOrder({
      identifiers: [
        { type: 'dns', value: options.domain },
        { type: 'dns', value: `*.${options.domain}` },
      ],
    });
  }
  if (order.status === 'invalid') throw new Error('Invalid order!');
  const orderUrl = agent.locations.get(order);
  if (options.eventTarget) {
    dispatchEvent(options.eventTarget, 'order', order);
    if (orderUrl) {
      dispatchEvent(options.eventTarget, 'orderUrl', order);
    }
  }
  await authorizeOrder({ order, agent, eventTarget: options.eventTarget });
  order = await agent.fetchOrder(orderUrl);

  if (order.status === 'ready') {
    const csrDER = await createCSR({
      commonName: `*.${options.domain}`,
      altNames: [`*.${options.domain}`, options.domain],
      ...options.csr,
      jwk: csrJWK,
    });
    const csr = encodeBase64UrlAsString(csrDER);
    order = await agent.finalizeOrder(order, csr);
  }
  if (order.status !== 'valid') throw new Error('Order not valid?');
  const certificate = await agent.fetchCertificate(order);
  return certificate;
}
