import { asUint8Array } from '../../../../inputs/bytes.mjs';
import { nativeArgon2id } from '../../../../providers/ecmascript/node-crypto.mjs';

const UINT32 = 0xffffffff;
const EMPTY = new Uint8Array(0);

function validate(memoryKiB, passes, lanes) {
  if (!Number.isInteger(lanes) || lanes < 1 || lanes > 0xffffff
      || !Number.isInteger(memoryKiB) || memoryKiB < 8 * lanes || memoryKiB > UINT32
      || !Number.isInteger(passes) || passes < 1 || passes > UINT32) {
    throw new RangeError('Invalid RFC 9106 Argon2id parameters');
  }
}

export function workspaceBytes(memoryKiB, lanes) {
  validate(memoryKiB, 1, lanes);
  return Math.floor(memoryKiB / (4 * lanes)) * 4 * lanes * 1024;
}

export function derive(password, salt, options) {
  const { memoryKiB, passes, lanes, length, memoryLimit } = options;
  validate(memoryKiB, passes, lanes);
  if (!Number.isInteger(length) || length < 4 || length > UINT32
      || !Number.isSafeInteger(memoryLimit) || workspaceBytes(memoryKiB, lanes) + length > memoryLimit) {
    throw new RangeError('Argon2id memory or output exceeds the caller budget');
  }
  const message = asUint8Array(password);
  const nonce = asUint8Array(salt);
  const secret = options.secret === undefined ? EMPTY : asUint8Array(options.secret);
  const associatedData = options.associatedData === undefined ? EMPTY : asUint8Array(options.associatedData);
  if (nonce.length < 8 || [message, nonce, secret, associatedData].some(input => input.length > UINT32)) {
    throw new RangeError('Invalid Argon2id password, salt, secret or associated-data length');
  }
  return nativeArgon2id({
    message, nonce, secret, associatedData, parallelism: lanes,
    tagLength: length, memory: memoryKiB, passes,
  });
}
