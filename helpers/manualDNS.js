/** @return {EventTarget} */
export function buildEventTarget() {
  const eventTarget = new EventTarget();

  eventTarget.addEventListener('dnsrecordneeded', (event) => {
    const { value, domain } = event.detail;
    const output = [
      'Add the following on the nameserver: ',
      '',
      `Domain: ${domain}`,
      `Value: ${value}`,
      '',
      'This automatic detection process will start after 10 seconds.',
    ].join('\n');
    console.log(output);
    event.waitUntil(new Promise((resolve) => {
      setTimeout(resolve, 10_000);
    }));
  });
  return eventTarget;
}
