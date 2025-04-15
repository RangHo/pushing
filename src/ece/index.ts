/**
 * Supported content encodings in encrypted Content-Encoding for HTTP.
 *
 * - `aesgcm` is the [second draft][1] of the standard that is used in some services (e.g. Mastodon).
 * - `aes128gcm` is the current standard as per [RFC 8188][2].
 *
 * [1]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-encryption-encoding-02
 * [2]: https://datatracker.ietf.org/doc/html/rfc8188
 */
export type ContentEncoding = 'aesgcm' | 'aes128gcm';

export abstract class ECE {
  abstract encrypt(data: Uint8Array, seq?: number): Uint8Array;

  abstract decrypt(data: Uint8Array, seq?: number): Uint8Array;
}

export abstract class ECEHeader {
  static fromBytes(bytes: Uint8Array): ECEHeader {
    throw new TypeError('Cannot instantiate an abstract class.');
  }

  abstract toBytes(): Uint8Array;
}

export function encrypt(message: ArrayBuffer, encoding?: ContentEncoding) {
  switch (encoding ?? 'aes128gcm') {
    case 'aes128gcm':
      break;
    case 'aesgcm':
      break;
    default:
      throw new Error('Unsupported content encoding: ' + encoding);
  }
}
