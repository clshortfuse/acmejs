import test from 'ava';

import { encodeBase64UrlAsString } from '../../utils/base64.js';

test('rfc7516 A.1.1', (t) => {
  const protectedHeader = { alg: 'RSA-OAEP', enc: 'A256GCM' };
  t.is(encodeBase64UrlAsString(JSON.stringify(protectedHeader)), 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ');
});

test('rfc7516 A.1.2', (t) => {
  const protectedHeader = { alg: 'RSA-OAEP', enc: 'A256GCM' };
  t.is(encodeBase64UrlAsString(JSON.stringify(protectedHeader)), 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ');
});
