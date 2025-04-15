import { concat } from './utilities';

describe('concat', () => {
  it('concatenates multiple Uint8Arrays into a single Uint8Array', () => {
    const arr1 = new Uint8Array([1, 2, 3]);
    const arr2 = new Uint8Array([4, 5, 6]);
    const arr3 = new Uint8Array([7, 8, 9]);
    const result = concat(arr1, arr2, arr3);
    expect(result).toStrictEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
  });
});
