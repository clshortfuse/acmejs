import { createHS256JWK } from '../../lib/jwa.js';
import { derFromPEM, derFromPKCS8, formatPEM, jwkFromPKCS8, jwkFromRSAPrivateKey, pemFromPKCS8, pkcs8FromJWK } from '../../utils/certificate.js';
import { importJWK } from '../../utils/crypto.js';
import test from '../tester.js';

test('importJWK()', async (t) => {
  const jwk = createHS256JWK({ k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow' });
  const key = await importJWK(jwk, { name: 'HMAC', hash: 'SHA-256' });
  t.truthy(key);
});

test('jwkFromPKCS8() - rsa', async (t) => {
  const pem = `-----BEGIN PRIVATE KEY-----
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
    -----END PRIVATE KEY-----`;
  const der = derFromPKCS8(pem);
  const jwk = await jwkFromPKCS8(der, { name: 'RSA-PSS', hash: 'SHA-256' });
  t.is(jwk.kty, 'RSA');
  t.is(jwk.n, 'w9LT1f3btr37Y7149bf4F0yt_bDQVazgBG_4ys12nvl2tB_ty4WWkCEDTHwAogUoCH2VLxBm_u06l1kKaC6BUf0ezLxlnEpPfCcq1bb3g_GZmWMiLUmO5toXGrKgBYisjqLleb88kXvO_5RMs8waRd20EOCA2kLvivR4-XyrlOq6znjobHZyXPlXQ0C0nB8bzKC2fVbbfqCvSeP7Ti8K-AhvJIQ5QVEXAWOoD3C6N3T1NPUlvunLV9nF-JpF8ejv9JpnU5mnK_77udCnUTJXhXmWDljwBIYTH8sMm07swYj1SGVT_FhQkijTG34tUvQPT3Qap3m8MB4V9_4bBAbdgQ');

  t.is(jwk.e, 'AQAB');
  t.is(jwk.d, 'BEI1P6nf6Zs7mJlyBDv-Pfl5rjL2cOqLy6TovvZVblMkCPpJyFuNIPDK2tK2i897ZaXfhPDBIKmllM2Hq6jZQKB110OAnTPDg0JxzMiIHPs32S1d_KilHjGff4Hjd4NXp1l1Dp8BUPOllorR2TYm2x6dcCGFw9lhTr8O03Qp4hjn84VjGIWADYCk83mgS4nRsnHkdiqYnWx1AjKlY51yEK6RcrDMi0Th2RXrrINoC35sVv-APt2rkoMGi52RwTEseA1KZGFrxjq61ReJif6p2VXEcvHeX6CWLx014LGk43z6Q28P6HgeEVEfIjyqCUea5Du_mYb_QsRSCosXLxBqwQ');
  t.is(jwk.p, '9fn3QvWYjK1SPpJuzcdgigZ_Kyaw5lIeUm159jGCXa1HfG2DZ2ZAoCjIMVV7Lya25lTq28trcToqrnWZJOZg9xOTv0GVj1kC4EbvLnmDaaGwF_TUYDX2e62Q_vNb4eTH2Yl37mTrs79vYmYVNKKsmfcu-Xh5C3a3qzZMGDnuWlE');
  t.is(jwk.q, 'y82qQ4tTcZAYLI_YojuClGu47w-CY0ahcuGYY_420L5bzNBf7hae7MVXBxseK9dQvuogm4V-LvmbrtBxo0-HfoTV5oBssUfHyFFcTpTrQ5FSWubDgWSu9__fzAXirrHZiT0YWpWUHzFCUViKBFQzIX4N7Vv6wY-UWALT9nU1VDE');
  t.is(jwk.dp, 'OzzKvnZ1GZP4FZegVbBpYHQ2FgdIXP9zy_gPginkMnkzmRSqq7ElaSzJIZBrjSxuqcPTl8FCi88tTjyF-Cv_OCGf2FSMFyyhk6-hlHixHDRTO0G8D7uPM7PWEoA7JYi6VHpVxrTJSs2UnoblHnr6xE2SI4RO6mLZ0sLNypvQ-jE');
  t.is(jwk.dq, 'ZyNHvTLvIZN4iGSrjz5qkM4LIwBIThFadxbv1fq6pt0O_BGf2o-cEdq0diYlGK64cEVwBwSBnSg4vzlBqRIAUejLjwEDAJyA4EE8Y5A9l04dzV7nJb5cRak6CrgXxay_mBJRFtaHxVlaZGxYPGSYE6UFS0-3EOmmevvDZQBf4qE');
  t.is(jwk.qi, '0ZF6Vavz28-8wLO6SP3w8NmpHk7K9tGEvUfQ30SgDx4G7qPIgfPrbB4OP_E0qCfsIImi3sCPpjvUMQdVVZyPOIMuB-rV3ZOxkrzxEUOrpOpR48FZbL7RN90yRQsAsrp9e4iv8QwB3VxLe7X0TDqqnRyqrc_osGzuS2ZcHOKmCU8');
  t.is(jwk.alg, 'PS256');
});

test('pkcs8FromJWK() - RSA-PSS', async (t) => {
  const pem = formatPEM(`-----BEGIN PRIVATE KEY-----
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
    -----END PRIVATE KEY-----`);

  const jwk = {
    kty: 'RSA',
    alg: 'PS256',
    n: 'w9LT1f3btr37Y7149bf4F0yt_bDQVazgBG_4ys12nvl2tB_ty4WWkCEDTHwAogUoCH2VLxBm_u06l1kKaC6BUf0ezLxlnEpPfCcq1bb3g_GZmWMiLUmO5toXGrKgBYisjqLleb88kXvO_5RMs8waRd20EOCA2kLvivR4-XyrlOq6znjobHZyXPlXQ0C0nB8bzKC2fVbbfqCvSeP7Ti8K-AhvJIQ5QVEXAWOoD3C6N3T1NPUlvunLV9nF-JpF8ejv9JpnU5mnK_77udCnUTJXhXmWDljwBIYTH8sMm07swYj1SGVT_FhQkijTG34tUvQPT3Qap3m8MB4V9_4bBAbdgQ',
    e: 'AQAB',
    d: 'BEI1P6nf6Zs7mJlyBDv-Pfl5rjL2cOqLy6TovvZVblMkCPpJyFuNIPDK2tK2i897ZaXfhPDBIKmllM2Hq6jZQKB110OAnTPDg0JxzMiIHPs32S1d_KilHjGff4Hjd4NXp1l1Dp8BUPOllorR2TYm2x6dcCGFw9lhTr8O03Qp4hjn84VjGIWADYCk83mgS4nRsnHkdiqYnWx1AjKlY51yEK6RcrDMi0Th2RXrrINoC35sVv-APt2rkoMGi52RwTEseA1KZGFrxjq61ReJif6p2VXEcvHeX6CWLx014LGk43z6Q28P6HgeEVEfIjyqCUea5Du_mYb_QsRSCosXLxBqwQ',
    p: '9fn3QvWYjK1SPpJuzcdgigZ_Kyaw5lIeUm159jGCXa1HfG2DZ2ZAoCjIMVV7Lya25lTq28trcToqrnWZJOZg9xOTv0GVj1kC4EbvLnmDaaGwF_TUYDX2e62Q_vNb4eTH2Yl37mTrs79vYmYVNKKsmfcu-Xh5C3a3qzZMGDnuWlE',
    q: 'y82qQ4tTcZAYLI_YojuClGu47w-CY0ahcuGYY_420L5bzNBf7hae7MVXBxseK9dQvuogm4V-LvmbrtBxo0-HfoTV5oBssUfHyFFcTpTrQ5FSWubDgWSu9__fzAXirrHZiT0YWpWUHzFCUViKBFQzIX4N7Vv6wY-UWALT9nU1VDE',
    dp: 'OzzKvnZ1GZP4FZegVbBpYHQ2FgdIXP9zy_gPginkMnkzmRSqq7ElaSzJIZBrjSxuqcPTl8FCi88tTjyF-Cv_OCGf2FSMFyyhk6-hlHixHDRTO0G8D7uPM7PWEoA7JYi6VHpVxrTJSs2UnoblHnr6xE2SI4RO6mLZ0sLNypvQ-jE',
    dq: 'ZyNHvTLvIZN4iGSrjz5qkM4LIwBIThFadxbv1fq6pt0O_BGf2o-cEdq0diYlGK64cEVwBwSBnSg4vzlBqRIAUejLjwEDAJyA4EE8Y5A9l04dzV7nJb5cRak6CrgXxay_mBJRFtaHxVlaZGxYPGSYE6UFS0-3EOmmevvDZQBf4qE',
    qi: '0ZF6Vavz28-8wLO6SP3w8NmpHk7K9tGEvUfQ30SgDx4G7qPIgfPrbB4OP_E0qCfsIImi3sCPpjvUMQdVVZyPOIMuB-rV3ZOxkrzxEUOrpOpR48FZbL7RN90yRQsAsrp9e4iv8QwB3VxLe7X0TDqqnRyqrc_osGzuS2ZcHOKmCU8',
  };
  const pkcs8 = await pkcs8FromJWK(jwk, { name: 'RSA-PSS', hash: 'SHA-256' });
  const result = pemFromPKCS8(pkcs8);
  t.is(pem, result);
});

test('pkcs8FromJWK() - RSA', async (t) => {
  const pem = formatPEM(`-----BEGIN PRIVATE KEY-----
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
    -----END PRIVATE KEY-----`);

  const jwk = {
    kty: 'RSA',
    alg: 'PS256',
    n: 'w9LT1f3btr37Y7149bf4F0yt_bDQVazgBG_4ys12nvl2tB_ty4WWkCEDTHwAogUoCH2VLxBm_u06l1kKaC6BUf0ezLxlnEpPfCcq1bb3g_GZmWMiLUmO5toXGrKgBYisjqLleb88kXvO_5RMs8waRd20EOCA2kLvivR4-XyrlOq6znjobHZyXPlXQ0C0nB8bzKC2fVbbfqCvSeP7Ti8K-AhvJIQ5QVEXAWOoD3C6N3T1NPUlvunLV9nF-JpF8ejv9JpnU5mnK_77udCnUTJXhXmWDljwBIYTH8sMm07swYj1SGVT_FhQkijTG34tUvQPT3Qap3m8MB4V9_4bBAbdgQ',
    e: 'AQAB',
    d: 'BEI1P6nf6Zs7mJlyBDv-Pfl5rjL2cOqLy6TovvZVblMkCPpJyFuNIPDK2tK2i897ZaXfhPDBIKmllM2Hq6jZQKB110OAnTPDg0JxzMiIHPs32S1d_KilHjGff4Hjd4NXp1l1Dp8BUPOllorR2TYm2x6dcCGFw9lhTr8O03Qp4hjn84VjGIWADYCk83mgS4nRsnHkdiqYnWx1AjKlY51yEK6RcrDMi0Th2RXrrINoC35sVv-APt2rkoMGi52RwTEseA1KZGFrxjq61ReJif6p2VXEcvHeX6CWLx014LGk43z6Q28P6HgeEVEfIjyqCUea5Du_mYb_QsRSCosXLxBqwQ',
    p: '9fn3QvWYjK1SPpJuzcdgigZ_Kyaw5lIeUm159jGCXa1HfG2DZ2ZAoCjIMVV7Lya25lTq28trcToqrnWZJOZg9xOTv0GVj1kC4EbvLnmDaaGwF_TUYDX2e62Q_vNb4eTH2Yl37mTrs79vYmYVNKKsmfcu-Xh5C3a3qzZMGDnuWlE',
    q: 'y82qQ4tTcZAYLI_YojuClGu47w-CY0ahcuGYY_420L5bzNBf7hae7MVXBxseK9dQvuogm4V-LvmbrtBxo0-HfoTV5oBssUfHyFFcTpTrQ5FSWubDgWSu9__fzAXirrHZiT0YWpWUHzFCUViKBFQzIX4N7Vv6wY-UWALT9nU1VDE',
    dp: 'OzzKvnZ1GZP4FZegVbBpYHQ2FgdIXP9zy_gPginkMnkzmRSqq7ElaSzJIZBrjSxuqcPTl8FCi88tTjyF-Cv_OCGf2FSMFyyhk6-hlHixHDRTO0G8D7uPM7PWEoA7JYi6VHpVxrTJSs2UnoblHnr6xE2SI4RO6mLZ0sLNypvQ-jE',
    dq: 'ZyNHvTLvIZN4iGSrjz5qkM4LIwBIThFadxbv1fq6pt0O_BGf2o-cEdq0diYlGK64cEVwBwSBnSg4vzlBqRIAUejLjwEDAJyA4EE8Y5A9l04dzV7nJb5cRak6CrgXxay_mBJRFtaHxVlaZGxYPGSYE6UFS0-3EOmmevvDZQBf4qE',
    qi: '0ZF6Vavz28-8wLO6SP3w8NmpHk7K9tGEvUfQ30SgDx4G7qPIgfPrbB4OP_E0qCfsIImi3sCPpjvUMQdVVZyPOIMuB-rV3ZOxkrzxEUOrpOpR48FZbL7RN90yRQsAsrp9e4iv8QwB3VxLe7X0TDqqnRyqrc_osGzuS2ZcHOKmCU8',
  };
  const pkcs8 = await pkcs8FromJWK(jwk, { name: 'RSA-PSS', hash: 'SHA-256' });
  const result = pemFromPKCS8(pkcs8);
  t.is(pem, result);
});

test('jwkFromRSAPrivateKey()', async (t) => {
  const pem = `-----BEGIN RSA PRIVATE KEY-----
  MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
  KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
  o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
  TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
  9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
  v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
  /5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
  -----END RSA PRIVATE KEY-----`;
  const der = derFromPEM(pem);
  const jwk = await jwkFromRSAPrivateKey(der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
  t.is(jwk.kty, 'RSA');
  t.is(jwk.alg, 'RS256');
  t.is(jwk.d, 'IJLixBy2qpFoS4DSmoEmo3qGy0t6z09AIJtH-5OeRV1be-N4cDYJKffGzDa88vQENZiRm0GRq6a-HPGQMd2kTQ');
  t.is(jwk.dp, 'bYSzn3Py6AasNj6nEtCfB-i1p3F35TK_87DlPSrmAgk');
  t.is(jwk.dq, 'yS4RaI9YG8EWx_2w0T67ZUVAw8eOMB6BIUg0Xcu-3ok');
  t.is(jwk.e, 'AQAB');
  t.is(jwk.n, 'qPfgaTEWEP3S9w0tgsicURfo-nLW09_0KfOPinhYZ4ouzU-3xC4pSlEp8Ut9FgL0AgqNslNaK34Kq-NZjO9DAQ');
  t.is(jwk.p, 'oxK_MgGeeLui385KJ7ZOYktjhLBNAB69fKwTZFsUNh0');
  t.is(jwk.q, 'AQlBGkUJzJ26e_ZsQ1w3-gFNHDf0TwY2_akhw3FmRxs1');
  t.is(jwk.qi, 'E6z_k6I-ChN1LLttwX0galITxmAYrOBhBVl433tgTTQ');
});
