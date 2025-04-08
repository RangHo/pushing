import { randomBytes } from '@noble/ciphers/webcrypto';
import { p256 } from '@noble/curves/p256';
import { base64url } from '@scure/base';

export class VAPIDKeyPair {
  readonly privateKey: Uint8Array;

  readonly publicKey: Uint8Array;

  constructor(privateKey: Uint8Array) {
    this.privateKey = privateKey;
    this.publicKey = p256.getPublicKey(privateKey, false);
  }

  static generateRandom() {
    const priv = p256.utils.randomPrivateKey();
    return new VAPIDKeyPair(priv);
  }

  toBase64Url() {
    const priv = base64url.encode(this.privateKey);
    const pub = base64url.encode(this.publicKey);

    return { privateKey: priv, publicKey: pub };
  }
}
