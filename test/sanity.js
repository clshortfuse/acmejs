import test from './tester.js';

test('sync test', (t) => {
  t.pass();
});

test('async test', async (t) => {
  const foo = Promise.resolve('foo');
  t.is(await foo, 'foo');
});
