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
  /** @type {(ChallengeBase & PendingChallenge & (DNSChallenge|HttpChallenge))[]} */
  const challegesToValidate = [];
  const completedChallenges = [];
  const processingChallenges = [];
  const pendingChallenges = [];
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
      if (challenge.type !== 'dns-01' && challenge.type !== 'http-01') continue;
      const authorization = await agent.buildKeyAuthorization(challenge);
      if (challenge.type === 'dns-01') {
        if (eventTarget) {
          await dispatchExtendableEvent(eventTarget, 'dnsrecordneeded', {
            name: '_acme-challenge',
            value: authorization,
            domain: authz.identifier.value,
          });
        }
      } else if (eventTarget) {
        await dispatchExtendableEvent(eventTarget, 'httpresourceneeded', {
          name: challenge.token,
          value: authorization,
          domain: authz.identifier.value,
        });
      }
      pendingChallenges.push({
        challenge,
        authorization,
        identifier: authz.identifier.value,
      });
    }
  }

  const attemptTimestamp = new Map();
  await Promise.race(pendingChallenges.map(async function verifyChallenge(pendingChallenge) {
    if (challegesToValidate.length) return;
    const { challenge, authorization, identifier } = pendingChallenge;
    const now = performance.now();
    let passed = false;
    if (challenge.type === 'dns-01') {
      passed = await checkDnsTxt(`_acme-challenge.${identifier}`, authorization);
    } else {
      try {
        const httpResponse = await fetch(`http://${identifier}/.well-known/acme-challenge/${challenge.token}`);
        if (httpResponse.ok) {
          const data = await httpResponse.text();
          passed = (data === authorization);
        }
      } catch (e) {
        console.warn(e);
      }
    }
    if (!passed) {
      if (challegesToValidate.length) return;
      if (attemptTimestamp.has(challenge)) {
        const timeSinceFirstAttempt = attemptTimestamp.get(challenge);
        if (now - timeSinceFirstAttempt >= 60_000) {
          throw new Error(`${challenge.type} verification failed for: ${identifier} ${authorization}`);
        }
      } else {
        attemptTimestamp.set(challenge, now);
      }
      await new Promise((resolve) => setTimeout(resolve, 5000));
      await verifyChallenge(pendingChallenge);
      return;
    }

    if (eventTarget) {
      await dispatchExtendableEvent(eventTarget, 'challengeverified', challenge);
    }
    challegesToValidate.push(challenge);
  }));

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
 * @typedef {Object} WildcardCertificateOrderOptions
 * @prop {boolean} tosAgreed
 * @prop {string} email
 * @prop {JWK|string|Uint8Array} accountKey Account JWK or PrivateKeyInformation (PKCS8)
 * @prop {string} domain
 * @prop {string} [orderUrl] existing order URL (blank for new)
 * @prop {string} [directoryUrl] defaults to LetsEncrypt Production
 * @prop {EventTarget} [eventTarget] used for async callbacks
 * @prop {string} [organizationName]
 * @prop {string} [organizationalUnitName]
 * @prop {string} [localityName]
 * @prop {string} [stateOrProvinceName]
 * @prop {string} [countryName]
 * @prop {JWK|string|Uint8Array} csrKey CSR JWK or PrivateKeyInformation (PKCS8)
 * @param {WildcardCertificateOrderOptions} options
 * @return {Promise<any>}
 */
export async function getWildcardCertificate(options) {
  /** @type {JWK} */
  let accountJWK;
  /** @type {JWK} */
  let csrJWK;

  if (typeof options.accountKey === 'string' || options.accountKey instanceof Uint8Array) {
    const der = derFromPrivateKeyInformation(options.accountKey);
    accountJWK = await jwkFromPrivateKeyInformation(der, suggestImportKeyAlgorithm(der));
  } else {
    accountJWK = options.accountKey;
  }

  if (typeof options.csrKey === 'string' || options.csrKey instanceof Uint8Array) {
    const der = derFromPrivateKeyInformation(options.csrKey);
    csrJWK = await jwkFromPrivateKeyInformation(der, suggestImportKeyAlgorithm(der));
  } else {
    csrJWK = options.csrKey;
  }

  const csrDER = await createCSR({
    commonName: `*.${options.domain}`,
    altNames: [`*.${options.domain}`, options.domain],
    countryName: options.countryName,
    localityName: options.localityName,
    organizationalUnitName: options.organizationalUnitName,
    organizationName: options.organizationName,
    stateOrProvinceName: options.stateOrProvinceName,
    jwk: csrJWK,
  });
  const csr = encodeBase64UrlAsString(csrDER);

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
    order = await agent.finalizeOrder(order, csr);
  }
  if (order.status !== 'valid') throw new Error('Order not valid?');
  const certificate = await agent.fetchCertificate(order);
  return certificate;
}

/**
 * @typedef {Object} HostnameCertificateOrderOptions
 * @prop {boolean} tosAgreed
 * @prop {string} email
 * @prop {JWK|string|Uint8Array} accountKey Account JWK or PrivateKeyInformation (PKCS8)
 * @prop {string} hostname
 * @prop {string} [orderUrl] existing order URL (blank for new)
 * @prop {string} [directoryUrl] defaults to LetsEncrypt Production
 * @prop {EventTarget} [eventTarget] used for async callbacks
 * @prop {string} [organizationName]
 * @prop {string} [organizationalUnitName]
 * @prop {string} [localityName]
 * @prop {string} [stateOrProvinceName]
 * @prop {string} [countryName]
 * @prop {JWK|string|Uint8Array} csrKey CSR JWK or PrivateKeyInformation (PKCS8)
 * @param {HostnameCertificateOrderOptions} options
 * @return {Promise<any>}
 */
export async function getHostnameCertificate(options) {
  /** @type {JWK} */
  let accountJWK;
  /** @type {JWK} */
  let csrJWK;

  if (typeof options.accountKey === 'string' || options.accountKey instanceof Uint8Array) {
    const der = derFromPrivateKeyInformation(options.accountKey);
    accountJWK = await jwkFromPrivateKeyInformation(der, suggestImportKeyAlgorithm(der));
  } else {
    accountJWK = options.accountKey;
  }

  if (typeof options.csrKey === 'string' || options.csrKey instanceof Uint8Array) {
    const der = derFromPrivateKeyInformation(options.csrKey);
    csrJWK = await jwkFromPrivateKeyInformation(der, suggestImportKeyAlgorithm(der));
  } else {
    csrJWK = options.csrKey;
  }

  const csrDER = await createCSR({
    commonName: options.hostname,
    countryName: options.countryName,
    localityName: options.localityName,
    organizationalUnitName: options.organizationalUnitName,
    organizationName: options.organizationName,
    stateOrProvinceName: options.stateOrProvinceName,
    jwk: csrJWK,
  });
  const csr = encodeBase64UrlAsString(csrDER);

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
        { type: 'dns', value: options.hostname },
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
    order = await agent.finalizeOrder(order, csr);
  }
  if (order.status !== 'valid') throw new Error('Order not valid?');
  const certificate = await agent.fetchCertificate(order);
  return certificate;
}
