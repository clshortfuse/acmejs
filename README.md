# acmejs

Zero-dependency ACME Client

# Compatiblity

Uses:

| Feature                                                                                            | Chrome | Firefox | Safari | NodeJS | Deno |
| -------------------------------------------------------------------------------------------------- | -----: | ------: | -----: | -----: | ---: |
| [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)                      |     37 |      34 |     11 | 15.0.0 | 1.17 |
| [Fetch](https://developer.mozilla.org/en-US/docs/Web/API/Fetch)                                    |     42 |      39 |   10.1 | 18.0.0 |  1.0 |
| [EventTarget](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/EventTarget)*           |     64 |      59 |     14 | 15.0.0 |  1.0 |
| [BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt)† |     67 |      68 |     14 | 10.4.0 |  1.0 |
|                                                                                                    |        |         |        |        |      |
| Supported                                                                                          |     67 |      68 |     14 | 18.0.0 | 1.17 |

*Used by helper functions
†Used by helper ASN1 operations

*Compatibility may be extended via polyfills (not included)*

# Libraries

* [ACMEClient](./lib/ACMEAgent.js)
* [JOSE Functions](./lib/jose.js)
* [JWA Functions](./lib/jwa.js)
* [JWE Functions](./lib/jwe.js) (incomplete)
* [JWK Functions](./lib/jwk.js)
* [JWS Functions](./lib/jws.js)
* [KeyStore](./lib/KeyStore.js)

# Helpers

* [JWK Import Functions](./helpers/jwkImporter.js)
* [name.com DNS API](./lib/nameDotCom.js)
* [Quick Certificate Order](./lib/quickOrder.js)

# Utilities

 * [ASN1 Encoder/Decoder](./utils/asn1.js)
 * [Base64 Encoder/Decoder](./utils/base64.js)
 * [Bit Functions](./utils/bit.js)
 * [SubtleCrypto NodeJS Wrapper](./utils/crypto.js)
 * [DNS Resolver](./utils/dns.js)
 * [PKCS1, PKCS8, PKCS10 Functions](./utils/pkcs8.js)
 * [UTF-8 Decoder](./utils/utf8.js)

# Usage


# Quick Order with name.com (defaults to Lets Encrypt ACME);

````js
import { buildEventTarget } from '@shortfuse/acmejs/helpers/nameDotCom.js';
import { getWildcardCertificate } from '@shortfuse/acmejs/helpers/quickOrder.js';

// as JWK
const ACCOUNT_PRIVATE_KEY = {
  alg: 'ES256',
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
};

// as PEM
const CSR_PRIVATE_KEY = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDD0tPV/du2vftjvXj1t/gXTK39
sNBVrOAEb/jKzXae+Xa0H+3LhZaQIQNMfACiBSgIfZUvEGb+7TqXWQpoLoFR/R7MvGWcSk98JyrV
tveD8ZmZYyItSY7m2hcasqAFiKyOouV5vzyRe87/lEyzzBpF3bQQ4IDaQu+K9Hj5fKuU6rrOeOhs
dnJc+VdDQLScHxvMoLZ9Vtt+oK9J4/tOLwr4CG8khDlBURcBY6gPcLo3dPU09SW+6ctX2cX4mkXx
6O/0mmdTmacr/vu50KdRMleFeZYOWPAEhhMfywybTuzBiPVIZVP8WFCSKNMbfi1S9A9PdBqnebww
HhX3/hsEBt2BAgMBAAECggEABEI1P6nf6Zs7mJlyBDv+Pfl5rjL2cOqLy6TovvZVblMkCPpJyFuN
IPDK2tK2i897ZaXfhPDBIKmllM2Hq6jZQKB110OAnTPDg0JxzMiIHPs32S1d/KilHjGff4Hjd4NX
p1l1Dp8BUPOllorR2TYm2x6dcCGFw9lhTr8O03Qp4hjn84VjGIWADYCk83mgS4nRsnHkdiqYnWx1
AjKlY51yEK6RcrDMi0Th2RXrrINoC35sVv+APt2rkoMGi52RwTEseA1KZGFrxjq61ReJif6p2VXE
cvHeX6CWLx014LGk43z6Q28P6HgeEVEfIjyqCUea5Du/mYb/QsRSCosXLxBqwQKBgQD1+fdC9ZiM
rVI+km7Nx2CKBn8rJrDmUh5SbXn2MYJdrUd8bYNnZkCgKMgxVXsvJrbmVOrby2txOiqudZkk5mD3
E5O/QZWPWQLgRu8ueYNpobAX9NRgNfZ7rZD+81vh5MfZiXfuZOuzv29iZhU0oqyZ9y75eHkLdrer
NkwYOe5aUQKBgQDLzapDi1NxkBgsj9iiO4KUa7jvD4JjRqFy4Zhj/jbQvlvM0F/uFp7sxVcHGx4r
11C+6iCbhX4u+Zuu0HGjT4d+hNXmgGyxR8fIUVxOlOtDkVJa5sOBZK73/9/MBeKusdmJPRhalZQf
MUJRWIoEVDMhfg3tW/rBj5RYAtP2dTVUMQKBgDs8yr52dRmT+BWXoFWwaWB0NhYHSFz/c8v4D4Ip
5DJ5M5kUqquxJWksySGQa40sbqnD05fBQovPLU48hfgr/zghn9hUjBcsoZOvoZR4sRw0UztBvA+7
jzOz1hKAOyWIulR6Vca0yUrNlJ6G5R56+sRNkiOETupi2dLCzcqb0PoxAoGAZyNHvTLvIZN4iGSr
jz5qkM4LIwBIThFadxbv1fq6pt0O/BGf2o+cEdq0diYlGK64cEVwBwSBnSg4vzlBqRIAUejLjwED
AJyA4EE8Y5A9l04dzV7nJb5cRak6CrgXxay/mBJRFtaHxVlaZGxYPGSYE6UFS0+3EOmmevvDZQBf
4qECgYEA0ZF6Vavz28+8wLO6SP3w8NmpHk7K9tGEvUfQ30SgDx4G7qPIgfPrbB4OP/E0qCfsIImi
3sCPpjvUMQdVVZyPOIMuB+rV3ZOxkrzxEUOrpOpR48FZbL7RN90yRQsAsrp9e4iv8QwB3VxLe7X0
TDqqnRyqrc/osGzuS2ZcHOKmCU8=
-----END PRIVATE KEY-----
`;

const NAME_DOT_COM_USERNAME = 'foo';
const NAME_DOT_COM_TOKEN = 'bar';

const certificate = await getWildcardCertificate({
  tosAgreed: true,
  domain: 'foo.com',
  jwk: ACCOUNT_PRIVATE_KEY,
  email: 'admin@foo.com',
  eventTarget: buildEventTarget(NAME_DOT_COM_USERNAME, NAME_DOT_COM_TOKEN),
  csr: {
    countryName: 'US',
    localityName: 'New York',
    organizationName: 'Foo Products',
    organizationalUnitName: 'IT',
    stateOrProvinceName: 'NY',
    jwk: CSR_PRIVATE_KEY,
  },
});

await store('foo-com.crt', certificate);
````

See [quickOrder.js](./helpers/quickOrder.js) source code for a working example.
