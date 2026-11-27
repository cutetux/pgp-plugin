import * as openpgp from 'openpgp';
import { settings } from '../shared.ts';

export const KEY_ALGORITHMS = ['rsa4096', 'ed25519Legacy', 'curve25519'] as const;
export type KeyAlgorithm = typeof KEY_ALGORITHMS[number];

export function isKeyAlgorithm(value: unknown): value is KeyAlgorithm {
  return typeof value === 'string' && (KEY_ALGORITHMS as readonly string[]).includes(value);
}

export function defaultKeyAlgorithm(): KeyAlgorithm {
  const configured = settings().generateKey;
  return isKeyAlgorithm(configured) ? configured : 'rsa4096';
}

export async function generateKeyPair(input: {
  algorithm: KeyAlgorithm;
  name: string;
  email: string;
  passphrase: string;
}): Promise<{ privateKey: string; revocationCertificate: string }> {
  const base = {
    userIDs: [{ name: input.name, email: input.email }],
    passphrase: input.passphrase,
    format: 'armored' as const,
  };

  switch (input.algorithm) {
    case 'ed25519Legacy':
      return openpgp.generateKey({
        ...base,
        type: 'ecc',
        curve: 'ed25519Legacy',
        subkeys: [{ type: 'ecc', curve: 'curve25519Legacy', sign: false }],
      });
    case 'curve25519':
      return openpgp.generateKey({
        ...base,
        type: 'curve25519',
        subkeys: [{ type: 'curve25519', sign: false }],
      });
    case 'rsa4096':
      return openpgp.generateKey({
        ...base,
        type: 'rsa',
        rsaBits: 4096,
      });
  }
}
