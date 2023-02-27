import { encodeBase64UrlAsString } from '../utils/base64.js';
import { digest } from '../utils/crypto.js';

import { extractPublicJWK } from './jwa.js';
import { thumbprintJWK } from './jwk.js';
import { signObject } from './jws.js';

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8555#section-4
 * @typedef {Object} AgentOptions
 * @prop {string} directoryUrl
 * @prop {JWK} jwk
 * @prop {string} [accountUrl]
 */

export default class ACMEAgent {
  /** @param {AgentOptions} options */
  constructor({ directoryUrl, accountUrl, jwk }) {
    this.directoryUrl = directoryUrl;
    this.accountUrl = accountUrl;
    this.jwk = jwk;
    /** @type {?Directory} */
    this.directory = null;
    /** @type {Map<string,Order>} */
    this.createdOrders = new Map();
    /** @type {Map<any, string>} */
    this.locations = new Map();

    /** @type {Set<Promise<any>>} */
    this.nonceLocks = new Set();
  }

  /**
   * @param {string} [newDirectoryUrl]
   * @return {Promise<Directory>}
   */
  async fetchDirectory(newDirectoryUrl) {
    if (newDirectoryUrl) {
      this.directoryUrl = newDirectoryUrl;
    }
    const response = await fetch(this.directoryUrl);
    if (!response.ok) throw new Error(`Status: ${response.status}`);
    const data = await response.json();
    this.directory = /** @type {Directory} */ (data);
    return this.directory;
  }

  /**
   * @param {Response} response
   * @return {string?} Null if none
   */
  storeNonceFromResponse(response) {
    const nonce = response.headers.get('replay-nonce');
    if (nonce) {
      this.nonce = nonce;
      return nonce;
    }
    return null;
  }

  /** @return {Promise<string>} */
  async fetchNonce() {
    const response = await fetch(this.directory.newNonce, {
      method: 'HEAD',
    });
    if (!response.ok) throw new Error(`Status: ${response.status}`);
    const nonce = this.storeNonceFromResponse(response);
    if (!nonce) throw new Error('No Nonce!');
    return nonce;
  }

  /** @return {Promise<string>} */
  async consumeNonce() {
    const nonce = this.nonce ?? await this.fetchNonce();
    this.nonce = null;
    return nonce;
  }

  async start() {
    await this.fetchDirectory();
  }

  /**
   * @param {string} url
   * @param {any} [payload]
   * @param {boolean} [jwk]
   * @return {Promise<Response>}
   */
  async postJOSE(url, payload = '', jwk = false) {
    // Build promise function
    const promiseFn = async () => {
      const fullUrl = new URL(url, this.directoryUrl).href;
      const jws = await signObject({
        payload,
        protected: {
          alg: this.jwk.alg,
          ...(jwk ? { jwk: extractPublicJWK(this.jwk) } : { kid: this.accountUrl }),
          nonce: await this.consumeNonce(),
          url: fullUrl,
        },
        jwk: this.jwk,
      });
      const body = JSON.stringify(jws);
      const response = await fetch(fullUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/jose+json',
          'Content-Length': body.length.toString(),
        },
        body,
      });

      this.storeNonceFromResponse(response);

      if (!response.ok) {
        const acmeError = /** @type {ACMEError} */ (await response.json());
        if (acmeError.type) {
          throw Object.assign(new Error(acmeError.type), acmeError);
        }
        throw new Error(response.statusText || response.status.toString());
      }
      return response;
    };
    if (this.nonceLocks.size) {
      await Promise.allSettled(this.nonceLocks);
    }
    // Schedule microtask
    const promiseExecution = promiseFn();
    this.nonceLocks.add(promiseExecution);
    try {
      return await promiseExecution;
    } finally {
      this.nonceLocks.delete(promiseExecution);
    }
  }

  /**
   * @param {AccountNewRequest} newAccountRequest
   * @return {Promise<Account>}
   */
  async createAccount(newAccountRequest) {
    const response = await this.postJOSE(this.directory.newAccount, newAccountRequest, true);
    const account = /** @type {Account} */ (await response.json());
    const location = response.headers.get('location');
    if (location) {
      this.accountUrl = location;
      this.locations.set(account, location);
    }
    this.account = account;
    return account;
  }

  /**
   * @param {AccountRequest} accountRequest
   * @return {Promise<Account>}
   */
  async updateAccount(accountRequest) {
    const response = await this.postJOSE(this.accountUrl, accountRequest);
    const account = /** @type {Account} */ (await response.json());
    const location = response.headers.get('location');
    if (location) {
      this.accountUrl = location;
    }
    this.locations.set(account, location ?? this.accountUrl);
    this.account = account;
    return account;
  }

  /** @return {Promise<Order[]>} */
  async fetchOrders() {
    const response = await this.postJOSE(this.account.orders);
    return await response.json();
  }

  /**
   * @param {OrderNewRequest} newOrderRequest
   * @return {Promise<Order>}
   */
  async createOrder(newOrderRequest) {
    const response = await this.postJOSE(this.directory.newOrder, newOrderRequest);
    const order = await response.json();
    const location = response.headers.get('location');
    if (location) {
      this.locations.set(order, location);
    }
    return order;
  }

  /**
   * @param {string} url
   * @return {Promise<Order>}
   */
  async fetchOrder(url) {
    const response = await this.postJOSE(url);
    const order = await response.json();
    this.locations.set(order, response.headers.get('location') || url);
    return order;
  }

  /**
   * @param {string} url
   * @return {Promise<Authorization>}
   */
  async fetchAuthorization(url) {
    const response = await this.postJOSE(url);
    const authorization = await response.json();
    this.locations.set(authorization, response.headers.get('location') || url);
    return authorization;
  }

  /**
   * Helper function
   * @param {string[]} urls
   * @return {Promise<Authorization[]>}
   */
  async fetchAuthorizations(urls) {
    return await Promise.all(urls.map((url) => this.fetchAuthorization(url)));
  }

  /**
   * @param {Challenge} challenge
   * @return {Promise<string>}
   */
  async buildKeyAuthorization(challenge) {
    const thumbprint = await thumbprintJWK(this.jwk);
    const keyAuthorization = `${challenge.token}.${thumbprint}`;
    if (challenge.type === 'http-01') return keyAuthorization;
    if (challenge.type === 'dns-01') {
      const rehashed = await digest('SHA-256', keyAuthorization);
      return encodeBase64UrlAsString(rehashed);
    }
    throw new Error('Unknown challenge type!');
  }

  /**
   * @param {Challenge} challenge
   * @return {Promise<Challenge>}
   */
  async validateChallenge(challenge) {
    const response = await this.postJOSE(challenge.url, {});
    return await response.json();
  }

  /**
   * @param {Order} order
   * @param {OrderFinalizeRequest['csr']} csr
   * @return {Promise<Order>}
   */
  async finalizeOrder(order, csr) {
    const response = await this.postJOSE(order.finalize, { csr });
    return await response.json();
  }

  /**
   * @see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.2
   * @param {Order} order
   * @return {Promise<string>}
   */
  async fetchCertificate(order) {
    const response = await this.postJOSE(order.certificate);
    return await response.text();
  }
}
