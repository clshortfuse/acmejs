/**
 * @param {number|bigint} number
 * @return {number}
 */
export function countBits(number) {
  let count = 0;
  // eslint-disable-next-line no-bitwise
  for (let int = BigInt(number); int !== 0n; int >>= 1n) {
    count += 1;
  }
  return count;
}
