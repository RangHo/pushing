import { ECE } from '.';
import {
  AES128GCM_CEK_INFO,
  AES128GCM_CEK_LENGTH,
  AES128GCM_IDLEN_LENGTH,
  AES128GCM_NONCE_INFO,
  AES128GCM_NONCE_LENGTH,
  AES128GCM_RS_DEFAULT,
  AES128GCM_RS_LENGTH,
  AES128GCM_RS_MAXIMUM,
  AES128GCM_RS_MINIMUM,
  AES128GCM_SALT_LENGTH,
} from '../constants';
import { concat } from '../utilities';
import { gcm } from '@noble/ciphers/aes';
import { expand, extract } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';

/**
 * AES-128-GCM encrypted content encoding provider.
 */
export class AES128GCM implements ECE {
  /**
   * Internal cache for the pseudo-random key (PRK).
   */
  private _prk: Uint8Array | null = null;

  /**
   * Pseudo-random key (PRK) derived from the input key material (IKM) and the salt identifed from the header.
   *
   * This value is derived by calculating the following::
   *
   *     PRK = HKDF-Extract(IKM, salt)
   */
  get prk() {
    if (!this._prk) {
      this._prk = extract(sha256, this.ikm, this.header.salt);
    }
    return this._prk;
  }

  /**
   * Internal cache for the content-encryption key (CEK).
   */
  private _cek: Uint8Array | null = null;

  /**
   * Content-encryption key (CEK) derived from the pseudo-random key (PRK).
   *
   * This value is derived by calculating the following with the length (L) parameter set to 16:
   *
   *     CEK = HKDF-Expand(PRK, cek_info || 0x01)
   */
  get cek() {
    if (!this._cek) {
      this._cek = expand(sha256, this.prk, AES128GCM_CEK_INFO, AES128GCM_CEK_LENGTH);
    }
    return this._cek;
  }

  /**
   * Internal cache for the base nonce value.
   */
  private _nonce: Uint8Array | null = null;

  /**
   * Nonce value for a given sequence number.
   *
   * This value is derived by calculating the following with the length (L) parameter set to 12:
   *
   *     NONCE = HKDF-Expand(PRK, nonce_info || 0x01) XOR SEQ
   *
   * @param seq - The sequence number of the record.
   * @returns The nonce value for the given sequence number.
   */
  nonce(seq: number) {
    if (!this._nonce) {
      this._nonce = expand(sha256, this.prk, AES128GCM_NONCE_INFO, AES128GCM_NONCE_LENGTH);
    }

    // While seq is a 96-bit integer, it is hard to work with in JavaScript.
    // Let's keep things as plain numbers...
    if (seq < 0 || seq > Number.MAX_SAFE_INTEGER) {
      throw new RangeError(`Invalid record sequence number: ${seq}`);
    }

    // Convert the raw number into 96-bit buffer.
    // Since JavaScript number's maximum safe integer value is smaller than u32,
    // we can just dump it into the last octets and call it a day.
    const seqBuffer = new ArrayBuffer(AES128GCM_NONCE_LENGTH);
    const seqView = new DataView(seqBuffer);
    seqView.setUint32(8, seq);
    const seqArray = new Uint8Array(seqBuffer, 0, AES128GCM_NONCE_LENGTH);
    const result = new Uint8Array(AES128GCM_NONCE_LENGTH);
    for (let i = 0; i < AES128GCM_NONCE_LENGTH; i++) {
      // XOR the nonce with the sequence number.
      // Note: since we create all arrays with set length, the indices are guaranteed to resolve.
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      result[i] = this._nonce[i]! ^ seqArray[i]!;
    }

    return result;
  }

  /**
   * Create a new AES128GCM instance with the given input key material (IKM) and optional header.
   *
   * @param ikm - The input key material (IKM) used to derive the PRK and CEK.
   * @param header - The header used to derive the salt and record size. If not provided, a default header will be created.
   */
  constructor(
    readonly ikm: Uint8Array,
    readonly header: AES128GCMHeader = new AES128GCMHeader()
  ) {}

  encrypt(data: Uint8Array, seq = 0) {
    const aes = gcm(this.cek, this.nonce(seq));
    const ciphertext = aes.encrypt(data);
    return concat(this.header.toBytes(), ciphertext);
  }

  decrypt(data: Uint8Array, seq = 0) {
    // Extract the ciphertext from the data.
    const ciphertext = data.subarray(this.header.byteLength, data.byteLength);
    const aes = gcm(this.cek, this.nonce(seq));
    return aes.decrypt(ciphertext);
  }
}

/**
 * Header describing the parameters for AES-128-GCM encrypted content encoding scheme.
 */
export class AES128GCMHeader {
  /**
   * The number of octets in the keyid.
   */
  get idlen() {
    return this.keyid.length;
  }

  /**
   * The total length of the header in bytes.
   */
  get byteLength() {
    return AES128GCM_SALT_LENGTH + AES128GCM_RS_LENGTH + AES128GCM_IDLEN_LENGTH + this.idlen;
  }

  /**
   * Create a new header with optional values.
   *
   * @param salt - A randomized salt value associated with this header.
   * @param rs - The record size in bytes.
   * @param keyid - The keying material identifier.
   */
  constructor(
    readonly salt: Uint8Array = randomBytes(AES128GCM_SALT_LENGTH),
    readonly rs: number = AES128GCM_RS_DEFAULT,
    readonly keyid: Uint8Array = new Uint8Array(0)
  ) {
    // Sanitize the salt length.
    if (salt.length !== AES128GCM_SALT_LENGTH) {
      throw new RangeError(
        `Invalid salt length: ${salt.length}, expected: ${AES128GCM_SALT_LENGTH}`
      );
    }

    // Sanitize the record size.
    if (rs < AES128GCM_RS_MINIMUM || rs > AES128GCM_RS_MAXIMUM) {
      throw new RangeError(
        `Invalid record size: ${rs}, expected: [${AES128GCM_RS_MINIMUM}, ${AES128GCM_RS_MAXIMUM}]`
      );
    }

    // Sanitize the keyid array.
    if (keyid.byteLength > 0xff) {
      throw new RangeError(
        `Invalid keyid size: ${keyid.byteLength}, the byte length must be less than 256.`
      );
    }
  }

  static fromBytes(value: Uint8Array) {
    const salt = value.subarray(0, AES128GCM_SALT_LENGTH);
    const rs = value.subarray(AES128GCM_SALT_LENGTH, AES128GCM_SALT_LENGTH + AES128GCM_RS_LENGTH);
    const idlen = value[AES128GCM_SALT_LENGTH + AES128GCM_RS_LENGTH] ?? 0;
    const keyid = value.subarray(
      AES128GCM_SALT_LENGTH + AES128GCM_RS_LENGTH + AES128GCM_IDLEN_LENGTH,
      AES128GCM_SALT_LENGTH + AES128GCM_RS_LENGTH + AES128GCM_IDLEN_LENGTH + idlen
    );

    const rsView = new DataView(rs.buffer, rs.byteOffset, rs.byteLength);
    const rsNumber = rsView.getUint32(0);
    return new this(salt, rsNumber, keyid);
  }

  toBytes(): Uint8Array {
    const rsBuffer = new ArrayBuffer(AES128GCM_RS_LENGTH);
    const rsView = new DataView(rsBuffer);
    rsView.setUint32(0, this.rs);

    const result = new Uint8Array(this.byteLength);
    result.set(this.salt, 0);
    result.set(new Uint8Array(rsBuffer), AES128GCM_SALT_LENGTH);
    result[AES128GCM_SALT_LENGTH + AES128GCM_RS_LENGTH] = this.idlen;
    result.set(this.keyid, AES128GCM_SALT_LENGTH + AES128GCM_RS_LENGTH + AES128GCM_IDLEN_LENGTH);

    return result;
  }
}
