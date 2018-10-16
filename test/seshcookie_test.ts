import * as crypto from 'crypto';

import { expect } from 'chai';

import * as seshcookie from '../lib/seshcookie';

describe('roundtrips', () => {
  it('works', () => {
    const key = crypto.randomBytes(16);
    const value = 'it was the best of times';
    const ciphertext = seshcookie.encrypt(Buffer.from(value), key);
    const plaintext = seshcookie.decrypt(ciphertext, key);
    expect(plaintext).to.equal(value);
  });
});
