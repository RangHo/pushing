import { AES128GCM_RS_MAXIMUM, AES128GCM_RS_MINIMUM } from '../constants';
import { AES128GCM, AES128GCMHeader } from './aes128gcm';
import { base64urlnopad } from '@scure/base';

// Raw example from the standard.
const plaintext = base64urlnopad.decode('SSBhbSB0aGUgd2FscnVzAg');
const ciphertext = base64urlnopad.decode(
  'I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg'
);

// Extracted intermediate header values from the example.
const header = base64urlnopad.decode('I1BsxtFttlv3u_Oo94xnmwAAEAAA');
const salt = base64urlnopad.decode('I1BsxtFttlv3u_Oo94xnmw');
const rs = 0x00001000;
const keyid = new Uint8Array(0);

// Extracted intermediate encryption values from the example.
const ikm = base64urlnopad.decode('yqdlZ-tYemfogSmv7Ws5PQ');
const prk = base64urlnopad.decode('zyeH5phsIsgUyd4oiSEIy35x-gIi4aM7y0hCF8mwn9g');
const cek = base64urlnopad.decode('_wniytB-ofscZDh4tbSjHw');
const nonce = base64urlnopad.decode('Bcs8gkIRKLI8GeI8');

describe('RFC 8188 acm128gcm header', () => {
  it('detects invalid salt size', () => {
    const invalidSalt = new Uint8Array(salt.length + 1);
    invalidSalt.set(salt);
    expect(() => new AES128GCMHeader(invalidSalt, rs, keyid)).toThrow();
  });

  it('detects invalid record size (too small)', () => {
    const invalidRs = AES128GCM_RS_MINIMUM - 1;
    expect(() => new AES128GCMHeader(salt, invalidRs, keyid)).toThrow();
  });

  it('detects invalid record size (too big)', () => {
    const invalidRs = AES128GCM_RS_MAXIMUM + 1;
    expect(() => new AES128GCMHeader(salt, invalidRs, keyid)).toThrow();
  });

  it('imports header from the binary ciphertext', () => {
    const target = AES128GCMHeader.fromBytes(ciphertext);
    expect(target.salt).toStrictEqual(salt);
    expect(target.rs).toStrictEqual(rs);
    expect(target.idlen).toStrictEqual(0);
    expect(target.keyid).toStrictEqual(keyid);
  });

  it('exports header to the binary ciphertext', () => {
    const target = new AES128GCMHeader(salt, rs, keyid);
    expect(target.toBytes()).toStrictEqual(header);
  });
});

describe('RFC 8188 acm128gcm encryption', () => {
  let target: AES128GCM;

  it('creates a new AES128GCM instance', () => {
    target = new AES128GCM(ikm, AES128GCMHeader.fromBytes(ciphertext));
  });

  it('calculates the correct PRK value', () => {
    expect(target.prk).toStrictEqual(prk);
  });

  it('calculates the correct CEK value', () => {
    expect(target.cek).toStrictEqual(cek);
  });

  it('calculates the correct NONCE value', () => {
    expect(target.nonce(0)).toStrictEqual(nonce);
  });

  it('decrypts to the correct plaintext value', () => {
    expect(target.decrypt(ciphertext, 0)).toStrictEqual(plaintext);
  });

  it('encrypts to the correct ciphertext value', () => {
    expect(target.encrypt(plaintext)).toStrictEqual(ciphertext);
  });
});
