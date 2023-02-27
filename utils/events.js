/**
 * @param {EventTarget} eventTarget
 * @param {string} type
 * @param {any} detail
 * @return {boolean} preventDefault called
 */
export function dispatchEvent(eventTarget, type, detail) {
  if (detail == null) {
    return eventTarget.dispatchEvent(new Event(type));
  }
  if (typeof CustomEvent === 'undefined') {
    const event = new Event(type);
    event.detail = detail;
    return eventTarget.dispatchEvent(event);
  }
  return eventTarget.dispatchEvent(new CustomEvent(type, { detail }));
}

/**
 * @param {EventTarget} eventTarget
 * @param {string} type
 * @param {any} detail
 * @return {Promise<boolean>} preventDefault called
 */
export async function dispatchExtendableEvent(eventTarget, type, detail) {
  let event;
  if (detail == null) {
    event = new Event(type);
  } else if (typeof CustomEvent === 'undefined') {
    event = new Event(type);
    event.detail = detail;
  } else {
    event = new CustomEvent(type, { detail });
  }
  let pendingPromise;
  event.waitUntil = (promise) => { pendingPromise = promise; };
  const result = eventTarget.dispatchEvent(event);
  if (pendingPromise) await pendingPromise;
  return result;
}
