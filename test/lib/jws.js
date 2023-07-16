import { createES256JWK, createES512JWK, createHS256JWK, createRS256JWK } from '../../lib/jwa.js';
import { decodeJSON, decodeJSONUnsafe, decodeString, decodeStringUnsafe, decodeUint8Array, decodeUint8ArrayUnsafe, signCompact, signObject, validate } from '../../lib/jws.js';
import { decodeBase64AsString, decodeBase64UrlAsArray, encodeBase64UrlAsString } from '../../utils/base64.js';
import { uint8ArrayFromUtf8 } from '../../utils/utf8.js';
import test from '../tester.js';

const RFC7515_APPENDIX_A_JWS = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC7515_PAYLOAD = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}';
const RFC7515_PAYLOAD_ENCODED = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';

const HS256_JWK = createHS256JWK({
  k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
});

const RS256_JWK = createRS256JWK({
  n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
  e: 'AQAB',
  d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
  p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
  q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
  dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
  dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
  qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
});

const ES256_PRIVATE_JWK = createES256JWK({
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
});

const ES256_PUBLIC_JWK = createES256JWK({
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
});

const ES512_PRIVATE_JWK = createES512JWK({
  x: 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
  y: 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
  d: 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
});

const ES512_PUBLIC_JWK = createES512JWK({
  x: 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
  y: 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
test('rfc7515 A.1.1 - HMAC SHA-256', async (t) => {
  const jws = await signCompact({
    protected: '{"typ":"JWT",\r\n "alg":"HS256"}',
    payload: RFC7515_PAYLOAD,
    jwk: HS256_JWK,
  });
  t.is(jws, RFC7515_APPENDIX_A_JWS);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.2
test('rfc7515 A.1.2 - HMAC SHA-256 - (string)', async (t) => {
  const compactJWS = RFC7515_APPENDIX_A_JWS;
  const payload = await decodeString(compactJWS, HS256_JWK);
  t.is(payload, RFC7515_PAYLOAD);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.2
test('rfc7515 A.1.2 - HMAC SHA-256 - (JSON)', async (t) => {
  const compactJWS = RFC7515_APPENDIX_A_JWS;
  const payload = await decodeJSON(compactJWS, HS256_JWK);
  t.deepEqual(payload, JSON.parse(RFC7515_PAYLOAD));
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.2
test('rfc7515 A.1.2 - HMAC SHA-256 - (fail)', async (t) => {
  const compactJWS = RFC7515_APPENDIX_A_JWS;
  const jwk = createHS256JWK({ k: 'xxxx' });
  await t.throwsAsync(() => decodeString(compactJWS, jwk));
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
test('rfc7515 A.2 - RSASSA-PKCS1-v1_5 SHA-256', async (t) => {
  const jws = await signObject({
    protected: { alg: 'RS256' },
    payload: RFC7515_PAYLOAD,
    jwk: RS256_JWK,
  });
  t.is(jws.signature, 'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw');
  await validate(jws, RS256_JWK);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3.1
test('rfc7515 A.3.1 - ECDSA P-256 SHA-256', async (t) => {
  const jws = await signCompact({
    protected: { alg: 'ES256' },
    payload: RFC7515_PAYLOAD,
    jwk: ES256_PRIVATE_JWK,
  });
  const result = await validate(jws, ES256_PUBLIC_JWK);
  t.is(decodeBase64AsString(result), RFC7515_PAYLOAD);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3.2
test('rfc7515 A.3.2 - ECDSA P-256 SHA-256', async (t) => {
  const result = await validate(
    'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
    ES256_PUBLIC_JWK,
  );
  t.is(result, RFC7515_PAYLOAD_ENCODED);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3.2
test('rfc7515 A.3.2 - ECDSA P-256 SHA-256 (fail)', async (t) => {
  await t.throwsAsync(() => validate(
    'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.XXXX',
    ES256_PUBLIC_JWK,
  ));
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.4.1
test('rfc7515 A.4.1 - ECDSA P-521 SHA-512', async (t) => {
  const jws = await signCompact({
    protected: { alg: 'ES512' },
    payload: RFC7515_PAYLOAD,
    jwk: ES512_PRIVATE_JWK,
  });
  const result = await validate(jws, ES512_PUBLIC_JWK);
  t.is(decodeBase64AsString(result), RFC7515_PAYLOAD);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.4.2
test('rfc7515 A.4.2 - ECDSA P-521 SHA-512', async (t) => {
  const result = await validate(
    'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn',
    ES512_PUBLIC_JWK,
  );
  t.is(result, 'UGF5bG9hZA');
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.4.2
test('rfc7515 A.4.2 - ECDSA P-521 SHA-512 (fail)', async (t) => {
  await t.throwsAsync(() => validate(
    'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.XXXX',
    ES512_PUBLIC_JWK,
  ));
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.5
test('rfc7515 A.5 - Unsecured', async (t) => {
  t.is(
    await validate('eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'),
    RFC7515_PAYLOAD_ENCODED,
  );
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.5
test('rfc7515 A.5 - Unsecured (fail: expected key)', async (t) => {
  await t.throwsAsync(() => validate(
    'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.',
    HS256_JWK,
  ));
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.5
test('rfc7515 A.5 - Unsecured (fail: unexpected signature)', async (t) => {
  await t.throwsAsync(() => validate(RFC7515_APPENDIX_A_JWS));
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.6.1
test('rfc7515 A.6.1 - Per-Signature Protected Headers', async (t) => {
  const rs256jws = await signObject({
    protected: { alg: 'RS256' },
    payload: RFC7515_PAYLOAD_ENCODED,
    jwk: RS256_JWK,
  });

  const es256jws = await signObject({
    protected: { alg: 'ES256' },
    payload: RFC7515_PAYLOAD_ENCODED,
    jwk: ES256_PRIVATE_JWK,
  });

  t.is(rs256jws.protected, 'eyJhbGciOiJSUzI1NiJ9');
  t.is(es256jws.protected, 'eyJhbGciOiJFUzI1NiJ9');
  // Must match
  t.is(rs256jws.payload, es256jws.payload);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.6.3
test('rfc7515 A.6.3 - Complete JOSE Header Values', async (t) => {
  const jws = await signObject({
    payload: RFC7515_PAYLOAD,
    signatures: [{
      protected: { alg: 'RS256' },
      header: { kid: '2010-12-29' },
      jwk: RS256_JWK,
    }, {
      protected: { alg: 'ES256' },
      header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
      jwk: ES256_PRIVATE_JWK,
    }],
  });

  const reference = {
    payload:
     'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    signatures: [{
      protected: 'eyJhbGciOiJSUzI1NiJ9',
      header: { kid: '2010-12-29' },
      signature: 'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw',
    }, {
      protected: 'eyJhbGciOiJFUzI1NiJ9',
      header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
      signature: 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
    }],
  };

  // Both should validate
  t.truthy(await validate(jws, RS256_JWK));
  t.truthy(await validate(jws, ES256_PUBLIC_JWK));

  // Because ECDSA is not deterministic (changes each generation) signatures will not match
  // For testing, strip the signatures and then compare
  t.notDeepEqual(jws, reference);
  for (const signature of [...jws.signatures, ...reference.signatures]) {
    if (signature.protected === 'eyJhbGciOiJFUzI1NiJ9') {
      signature.signature = '';
    }
  }
  t.deepEqual(jws, reference);
});

// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.7
test('rfc7515 A.7 - Flattened JWS JSON Serialization', async (t) => {
  const jws = await signObject({
    payload: RFC7515_PAYLOAD,
    signatures: [{
      protected: { alg: 'ES256' },
      header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
      jwk: ES256_PRIVATE_JWK,
    }],
  });

  const reference = {
    payload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    protected: 'eyJhbGciOiJFUzI1NiJ9',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
  };

  // Because ECDSA is not deterministic (changes each generation) signatures will not match
  // For testing, strip the signatures and then compare
  t.notDeepEqual(jws, reference);

  jws.signature = '';
  reference.signature = '';
  t.deepEqual(jws, reference);
});

test('encodePayload (JSON)', async (t) => {
  const payload = { foo: 'bar' };
  const jws = await signObject({
    payload,
    protected: { alg: 'none' },
  });
  const encodedPayload = encodeBase64UrlAsString(JSON.stringify(payload));
  t.is(jws.payload, encodedPayload);
});

test('match no signatures', async (t) => {
  const jws = await signObject({
    payload: RFC7515_PAYLOAD,
    signatures: [{
      protected: { alg: 'HS256' },
      jwk: HS256_JWK,
    }, {
      protected: { alg: 'RS256' },
      jwk: RS256_JWK,
    }],
  });
  await t.throwsAsync(() => validate(jws, ES256_PUBLIC_JWK));
});

test('decode unsafe string', async (t) => {
  const payload = 'Hello world!';
  const jws = await signObject({
    payload,
    signatures: [{
      protected: { alg: 'HS256' },
      jwk: HS256_JWK,
    }, {
      protected: { alg: 'RS256' },
      jwk: RS256_JWK,
    }],
  });
  t.is(payload, decodeStringUnsafe(jws));
});

test('decodeUint8Array', async (t) => {
  const payload = decodeBase64UrlAsArray(RFC7515_PAYLOAD_ENCODED);
  const jws = await signObject({
    payload,
    signatures: [{
      protected: { alg: 'HS256' },
      jwk: HS256_JWK,
    }, {
      protected: { alg: 'RS256' },
      jwk: RS256_JWK,
    }],
  });
  t.deepEqual(payload, await decodeUint8Array(jws, RS256_JWK));
});

test('decodeUint8ArrayUnsafe', async (t) => {
  const payload = decodeBase64UrlAsArray(RFC7515_PAYLOAD_ENCODED);
  const jws = await signObject({
    payload,
    signatures: [{
      protected: { alg: 'HS256' },
      jwk: HS256_JWK,
    }, {
      protected: { alg: 'RS256' },
      jwk: RS256_JWK,
    }],
  });
  t.deepEqual(payload, decodeUint8ArrayUnsafe(jws));
});

test('decode unsafe JSON', async (t) => {
  const payload = { foo: 'bar' };
  const jws = await signObject({
    payload,
    signatures: [{
      protected: { alg: 'HS256' },
      jwk: HS256_JWK,
    }, {
      protected: { alg: 'RS256' },
      jwk: RS256_JWK,
    }],
  });
  t.deepEqual(payload, decodeJSONUnsafe(jws));
});

// https://www.rfc-editor.org/rfc/rfc8725.html#CVE-2015-9235
test('CVE-2015-9235 - Replicate setup', async (t) => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { loggedInAs: 'admin', iat: 1_422_779_638 };
  const key = 'secretkey';
  const hmacKey = uint8ArrayFromUtf8(key);
  const symmetricalJWK = createHS256JWK({ k: hmacKey });
  const symmetricalJWS = await signCompact({
    protected: header,
    payload,
    jwk: symmetricalJWK,
  });
  t.deepEqual(symmetricalJWS, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.gzSraSYS8EXBxLN_oWnFSRgCzcmJmMjLiuyu5CSpyHI');

  t.deepEqual(await validate(symmetricalJWS, symmetricalJWK), 'eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9');
});

test('CVE-2015-9235 - Validation should fail if token specifies alg:none though JWK used', async (t) => {
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { loggedInAs: 'admin', iat: 1_422_779_638 };
  const key = 'secretkey';
  const hmacKey = uint8ArrayFromUtf8(key);
  const symmetricalJWK = createHS256JWK({ k: hmacKey });

  // Will not allow conflict when signing
  await t.throwsAsync(signCompact({
    protected: header,
    payload,
    jwk: symmetricalJWK,
  }));

  const noneJWS = await signCompact({
    protected: header,
    payload,
    jwk: null,
  });

  t.deepEqual(noneJWS, 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.');

  t.deepEqual(await validate(noneJWS, null), 'eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9');
  await t.throwsAsync(validate(noneJWS, symmetricalJWK));
});

test('CVE-2015-9235 - Tokens headers do not override key algorithm when validating', async (t) => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { loggedInAs: 'admin', iat: 1_422_779_638 };
  const publicKey = 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ';
  const symmetricalJWK = createHS256JWK({ k: publicKey });
  const symmetricalJWS = await signCompact({
    protected: header,
    payload,
    jwk: symmetricalJWK,
  });
  t.deepEqual(symmetricalJWS, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.OE2MlSdwscv4nwTVGpT8K8DqObPUcNHSMVoZ_e_YX3U');

  // Create Private JWK that has matching Public Key as previous HMAC
  const asymmetricalJWK = createRS256JWK({
    n: publicKey,
    e: 'AQAB',
    d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
    p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
    q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
    dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
    dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
    qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
  });

  const asymmetricalJWS = await signCompact({
    protected: header,
    payload,
    jwk: asymmetricalJWK,
  });

  t.deepEqual(asymmetricalJWS, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.jqp5oj5ByCAWCp8yQB1gCOjt3fBFEC9aQOC47Nrm_8D66G6syVupXQS6ym9QB-490Gj0K3ve5LmdLhLsNBQhacCCoH-TNmVD8hElcCbeS2g_moKjfl5TZ6fkDneptIZdlNW0HMY5frrkmQ0W6Jei3VKtOYsEX8DfLKZzG3FV2ODs5Istm2x7ObkbqVkOQsPpB15h1-x61VDTMLnL6TeOLVCiVX83Tp9YklLtDySZeQgfU7XhFB969OxMx49_zkZG_TKnctuxbH8kGOIKnyy7YTU1ecURhK_YqkTR8Z4OLoltEZxgSycIHmJx-CwQs4nHeU4igiE8OBUteX6e8uQz3w');

  // Keys only validate if match
  t.deepEqual(await validate(symmetricalJWS, symmetricalJWK), 'eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9');
  t.deepEqual(await validate(asymmetricalJWS, asymmetricalJWK), 'eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9');
  await t.throwsAsync(validate(symmetricalJWS, asymmetricalJWK));
  await t.throwsAsync(validate(asymmetricalJWS, symmetricalJWK));
});
