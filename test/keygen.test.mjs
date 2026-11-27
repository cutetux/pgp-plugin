import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { build } from 'esbuild';
import { mkdir } from 'node:fs/promises';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import * as openpgp from 'openpgp';

const outDir = 'node_modules/.cache/pgp-plugin-tests';
async function load(entryPoint) {
  await mkdir(outDir, { recursive: true });
  const outfile = `${outDir}/${basename(entryPoint, '.ts')}.mjs`;
  await build({
    entryPoints: [entryPoint],
    bundle: true,
    outfile,
    format: 'esm',
    platform: 'node',
    logLevel: 'silent',
    external: ['openpgp', 'hash-wasm'],
    alias: { '@plugin-host': './test/stubs/plugin-host.mjs' },
  });
  return import(pathToFileURL(outfile).href);
}

const { generateKeyPair, defaultKeyAlgorithm, KEY_ALGORITHMS } = await load('src/pgp/keygen.ts');
const stub = globalThis.__pluginHostStub;

beforeEach(() => {
  stub.settings = {};
});

test('the generate setting preselects the key type', () => {
  stub.settings = { generateKey: 'ed25519Legacy' };
  assert.equal(defaultKeyAlgorithm(), 'ed25519Legacy');
});

test('an unset or unknown setting falls back to RSA 4096', () => {
  assert.equal(defaultKeyAlgorithm(), 'rsa4096');
  stub.settings = { generateKey: 'dsa1024' };
  assert.equal(defaultKeyAlgorithm(), 'rsa4096');
});

const expected = {
  rsa4096: { primary: 'rsaEncryptSign', subkey: 'rsaEncryptSign' },
  ed25519Legacy: { primary: 'eddsaLegacy', subkey: 'ecdh' },
  curve25519: { primary: 'ed25519', subkey: 'x25519' },
};

for (const algorithm of KEY_ALGORITHMS) {
  test(`${algorithm} makes a key that can sign and encrypt`, async () => {
    const { privateKey: armored } = await generateKeyPair({
      algorithm,
      name: 'Test',
      email: 'test@example.com',
      passphrase: 'correct horse',
    });
    const privateKey = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: armored }),
      passphrase: 'correct horse',
    });

    assert.equal(privateKey.getAlgorithmInfo().algorithm, expected[algorithm].primary);
    assert.equal(privateKey.subkeys.length, 1);
    assert.equal(privateKey.subkeys[0].getAlgorithmInfo().algorithm, expected[algorithm].subkey);
    assert.deepEqual(privateKey.users[0].userID.email, 'test@example.com');

    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: 'hello' }),
      encryptionKeys: privateKey.toPublic(),
      signingKeys: privateKey,
    });
    const { data, signatures } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: encrypted }),
      decryptionKeys: privateKey,
      verificationKeys: privateKey.toPublic(),
    });
    assert.equal(data, 'hello');
    await signatures[0].verified;
  });
}
