import { decodeBase64AsArray, decodeBase64AsUtf8, encodeBase64AsArray, encodeBase64AsString } from '../../utils/base64.js';
import test from '../tester.js';

const textEncoder = new TextEncoder();

const FIXTURES = [
  { utf8: 'f', base64String: 'Zg==', base64UrlString: 'Zg' },
  { utf8: 'fo', base64String: 'Zm8=', base64UrlString: 'Zm8' },
  { utf8: 'foo', base64String: 'Zm9v', base64UrlString: 'Zm9v' },
  { utf8: '£', base64String: 'wqM=', base64UrlString: 'wqM' },
  { utf8: '€', base64String: '4oKs', base64UrlString: '4oKs' },
  { utf8: '🙈', base64String: '8J+ZiA==', base64UrlString: '8J-ZiA' },
  { utf8: '€A', base64String: '4oKsQQ==', base64UrlString: '4oKsQQ' },
  { utf8: '€AB', base64String: '4oKsQUI=', base64UrlString: '4oKsQUI' },
  { utf8: '€€', base64String: '4oKs4oKs', base64UrlString: '4oKs4oKs' },
  { utf8: 'foobar', base64String: 'Zm9vYmFy', base64UrlString: 'Zm9vYmFy' },
  { utf8: '€🙈', base64String: '4oKs8J+ZiA==', base64UrlString: '4oKs8J-ZiA' },
  { utf8: '🙈🙈', base64String: '8J+ZiPCfmYg=', base64UrlString: '8J-ZiPCfmYg' },
];

// Encode tests
for (const { utf8, base64String, base64UrlString } of FIXTURES) {
  for (const source of [utf8, textEncoder.encode(utf8)]) {
    const sourceType = typeof source === 'string' ? 'string' : 'Uint8Array';
    for (const outputType of ['String', 'Array']) {
      for (const useUrl of ['url', '']) {
        test(`encode ${sourceType} to base64${useUrl} ${outputType}: ${utf8}`, (t) => {
          if (outputType === 'String') {
            t.deepEqual(
              encodeBase64AsString(source, !!useUrl),
              useUrl ? base64UrlString : base64String,
            );
          } else {
            t.deepEqual(
              encodeBase64AsArray(source, !!useUrl),
              textEncoder.encode(useUrl ? base64UrlString : base64String),
            );
          }
        });
      }
    }
  }
}

// Decode tests
for (const { utf8, base64String } of FIXTURES) {
  for (const source of [base64String, textEncoder.encode(base64String)]) {
    const sourceType = typeof source === 'string' ? 'string' : 'Uint8Array';
    for (const outputType of ['String', 'Array']) {
      test(`decode base64 ${sourceType} to ${outputType}: ${utf8}`, (t) => {
        if (outputType === 'String') {
          t.deepEqual(
            decodeBase64AsUtf8(source, false),
            utf8,
          );
        } else {
          t.deepEqual(
            decodeBase64AsArray(source, false),
            textEncoder.encode(utf8),
          );
        }
      });
    }
  }
}

// Decode url tests
for (const { utf8, base64UrlString } of FIXTURES) {
  for (const source of [base64UrlString, textEncoder.encode(base64UrlString)]) {
    const sourceType = typeof source === 'string' ? 'string' : 'Uint8Array';
    for (const outputType of ['String', 'Array']) {
      for (const explicit of [true, null]) {
        test(`decode base64url ${explicit ? '(explicit)' : '(auto)'} ${sourceType} to ${outputType}: ${utf8}`, (t) => {
          if (outputType === 'String') {
            t.is(
              decodeBase64AsUtf8(source, explicit),
              utf8,
            );
          } else {
            t.deepEqual(
              decodeBase64AsArray(source, explicit),
              textEncoder.encode(utf8),
            );
          }
        });
      }
    }
  }
}
