/**
 * @param {string} name
 * @param {string} txt
 * @return {Promise<boolean>}
 */
export async function checkDnsTxt(name, txt) {
  const url = new URL('https://dns.google/resolve?');
  url.searchParams.set('name', name);
  url.searchParams.set('type', '16');
  url.searchParams.set('ct', 'application/x-javascript');
  url.searchParams.set('cd', 'false');
  const response = await fetch(url);
  const data = await response.json();
  for (const answer of data?.Answer ?? []) {
    if (answer.data === txt) return true;
  }
  return false;
}

// TODO: Implement DoH
// https://www.rfc-editor.org/rfc/rfc8484
