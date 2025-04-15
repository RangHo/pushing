/**
 * Number of bytes of the salt block used in 'aes128gcm' encryption.
 */
export const AES128GCM_SALT_LENGTH = 16;

/**
 * Number of bytes of the record size block used in 'aes128gcm' encryption.
 */
export const AES128GCM_RS_LENGTH = 4;

/**
 * Minimum valid value of the record size block used in 'aes128gcm' encryption.
 */
export const AES128GCM_RS_MINIMUM = 18;

/**
 * Maximum valid value of the record size block used in 'aes128gcm' encryption.
 */
export const AES128GCM_RS_MAXIMUM = 2 ** 36 - 31;

/**
 * Default value of the record size block used in 'aes128gcm' encryption.
 */
export const AES128GCM_RS_DEFAULT = 0x00001000;

/**
 * Number of bytes of the block that contains the length of the 'keyid' parameter used in 'aes128gcm' encryption.
 */
export const AES128GCM_IDLEN_LENGTH = 1;

/**
 * The info parameter to the HMAC-based key derivation function for the content-encryption key used in 'aes128gcm' encryption.
 *
 * This value is derived from the ASCII-encoded string:
 *
 *     Content-Encoding: aes128gcm\0
 */
export const AES128GCM_CEK_INFO = new Uint8Array([
  // C     o     n     t     e     n     t     -     E     n     c     o     d     i     n     g
  0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,
  // :    SP     a     e     s     1     2     8     g     c     m  NULL
  0x3a, 0x20, 0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x67, 0x63, 0x6d, 0x00,
]);

/**
 * Number of bytes of the content-encryption key used in 'aes128gcm' encryption.
 */
export const AES128GCM_CEK_LENGTH = 16;

/**
 * The info parameter to the HMAC-based key derivation function for the nonce used in 'aes128gcm' encryption.
 *
 * This value is derived from the ASCII-encoded string:
 *
 *     Content-Encoding: nonce\0
 */
export const AES128GCM_NONCE_INFO = new Uint8Array([
  // C     o     n     t     e     n     t     -     E     n     c     o     d     i     n     g
  0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,
  // :    SP     n     o     n     c     e  NULL
  0x3a, 0x20, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x00,
]);

/**
 * Number of bytes of the nonce value used in 'aes128gcm' encryption.
 */
export const AES128GCM_NONCE_LENGTH = 12;

/**
 * A Uint8Array containing a single byte with the value 0x01.
 */
export const UINT8ARRAY_ONE = new Uint8Array([0x01]);
