import test from 'ava';

test('sync test', (t) => {
  t.pass();
});

test('async test', async (t) => {
  const foo = Promise.resolve('foo');
  t.is(await foo, 'foo');
});
