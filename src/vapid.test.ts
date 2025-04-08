import { VAPIDKeyPair } from './vapid';

describe('VAPID key pair generator', () => {
  let keypair: VAPIDKeyPair;

  it('generates a VAPID key pair', () => {
    keypair = VAPIDKeyPair.generateRandom();

    expect(keypair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keypair.privateKey).toBeInstanceOf(Uint8Array);
  });

  it('has a public key of length 65', () => {
    expect(keypair.publicKey).toHaveLength(65);
  });

  it('has a private key of length 32', () => {
    expect(keypair.privateKey).toHaveLength(32);
  });
});
