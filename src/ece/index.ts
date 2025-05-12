import { NotImplementedError, UnsupportedError } from '../errors';

/**
 * Supported content encodings in encrypted Content-Encoding for HTTP.
 *
 * - `aes128gcm` is the current standard as per [RFC 8188][1].
 * - `aesgcm` is the [second draft][2] of the standard that is used in some services (e.g. Mastodon).
 * - `aesgcm128` is the [initial draft][3] of the standard and is NOT supported.
 *
 * [1]: https://datatracker.ietf.org/doc/html/rfc8188
 * [2]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-encryption-encoding-02
 * [3]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-encryption-encoding-00
 */
export type ContentEncoding = 'aes128gcm' | 'aesgcm' | 'aesgcm128';

/**
 * Abstract encrypted content encoding provider.
 */
export interface ECE {
  /**
   * Encrypt the given plaintext data into ciphertext.
   *
   * @param data - Plaintext data to encrypt.
   * @param seq - Sequence number of the record that is used to calculate encryption nonce.
   * @returns Encrypted payload.
   */
  encrypt(data: Uint8Array, seq?: number): Uint8Array;

  /**
   * Decrypt the given encrypted data into plaintext.
   *
   * @param data - Encrypted payload passed in a request or response.
   * @param seq - Seequence number of the record that is used to calculate decryption nonce.
   * @returns Decrypted plaintext data.
   */
  decrypt(data: Uint8Array, seq?: number): Uint8Array;
}

/**
 * Encrypt the given Web Push message.
 *
 * @param message - Message data to encrypt.
 * @param encoding - Type of encoding scheme to use.
 * @returns Encrypted message data.
 */
export function encrypt(_message: Uint8Array, encoding: ContentEncoding = 'aes128gcm') {
  switch (encoding) {
    case 'aes128gcm':
    case 'aesgcm':
      throw new NotImplementedError('Encryption is not yet supported.');
    case 'aesgcm128':
      throw new UnsupportedError(
        `'aesgcm128' is not supported. Please use 'aes128gcm' or 'aesgcm' instead.`
      );
    default:
      throw new TypeError(
        `Unrecognized encoding type: ${encoding}. Supported types are 'aes128gcm', 'aesgcm', and 'aesgcm128'.`
      );
  }
}

/**
 * Decrypt the given Web Push message.
 *
 * @param message - Message data to decrypt.
 * @param encoding - Type of encoding scheme to use.
 * @returns Decrypted message data.
 */
export function decrypt(_message: Uint8Array, encoding: ContentEncoding = 'aes128gcm') {
  switch (encoding) {
    case 'aes128gcm':
    case 'aesgcm':
      throw new NotImplementedError('Decryption is not yet supported.');
    case 'aesgcm128':
      throw new UnsupportedError(
        `'aesgcm128' is not supported. Please use 'aes128gcm' or 'aesgcm' instead.`
      );
    default:
      throw new TypeError(
        `Unrecognized encoding type: ${encoding}. Supported types are 'aes128gcm', 'aesgcm', and 'aesgcm128'.`
      );
  }
}
