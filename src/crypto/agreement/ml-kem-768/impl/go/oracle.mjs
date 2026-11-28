import { createPrivateKey, createPublicKey, encapsulate, decapsulate } from 'node:crypto';
import { readFileSync } from 'node:fs';

const cases = JSON.parse(readFileSync(0, 'utf8'));
const prefix = Buffer.from('3054020100300b060960864801650304040204428040', 'hex');

const results = cases.map(item => {
  const key = createPrivateKey({
    key: Buffer.concat([prefix, Buffer.from(item.seed, 'hex')]), format: 'der', type: 'pkcs8',
  });
  const publicKey = createPublicKey(key);
  const output = encapsulate(publicKey);
  return {
    public: publicKey.export({ format: 'der', type: 'spki' }).subarray(-1184).toString('hex'),
    decapsulated: decapsulate(key, Buffer.from(item.ciphertext, 'hex')).toString('hex'),
    ciphertext: output.ciphertext.toString('hex'),
    shared: output.sharedKey.toString('hex'),
    rejected: decapsulate(key, Buffer.from(item.damaged, 'hex')).toString('hex'),
  };
});
process.stdout.write(JSON.stringify(results));
