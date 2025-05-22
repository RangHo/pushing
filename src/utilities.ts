/**
 * Concatenate multiple Uint8Arrays into a single Uint8Array.
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Perform XOR operation on two Uint8Arrays of equal length.
 */
export function xor(lhs: Uint8Array, rhs: Uint8Array): Uint8Array {
  if (lhs.length !== rhs.length) {
    throw new Error('XOR operation requires Uint8Arrays of equal length.');
  }
  const result = new Uint8Array(lhs.length);
  for (let i = 0; i < lhs.length; i++) {
    // This is safe because we check the lengths above.
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    result[i] = lhs[i]! ^ rhs[i]!;
  }
  return result;
}
