import Agent from '../../lib/ACMEAgent.js';
import test from '../tester.js';

const LETS_ENCRYPT_STAGE_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory';

// TODO: Mock server

test('constructor', (t) => {
  const agent = new Agent({
    directoryUrl: LETS_ENCRYPT_STAGE_URL,
  });
  t.truthy(agent);
});

test('fetchDirectory', async (t) => {
  const agent = new Agent({
    directoryUrl: LETS_ENCRYPT_STAGE_URL,
  });
  const directory = await agent.fetchDirectory();
  t.truthy(directory);
  t.truthy(directory.newAccount);
  t.true(new URL(directory.newAccount) instanceof URL);
});

test('nonce', async (t) => {
  const agent = new Agent({
    directoryUrl: LETS_ENCRYPT_STAGE_URL,
  });
  const directory = await agent.fetchDirectory();
  const nonce = await agent.fetchNonce();
  t.truthy(nonce);
  t.log(nonce);
});
