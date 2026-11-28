// Return a fixed-length view using native typed-array accessors.
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const ByteArray = Uint8Array;
const WordArray = Uint32Array;
const elementAt = Function.prototype.call.bind(Uint8Array.prototype.at);

function accessor(prototype, key) {
  const { get } = Object.getOwnPropertyDescriptor(prototype, key);
  return Function.prototype.call.bind(get);
}

const getType = accessor(typedArrayPrototype, Symbol.toStringTag);
const getBuffer = accessor(typedArrayPrototype, 'buffer');
const getOffset = accessor(typedArrayPrototype, 'byteOffset');
const getLength = accessor(typedArrayPrototype, 'length');
const arrayBufferLength = accessor(ArrayBuffer.prototype, 'byteLength');

function fixedView(input, type, constructor) {
  if (getType(input) !== type) throw new TypeError(`Expected a ${type}`);
  const buffer = getBuffer(input);
  // This getter validates the ArrayBuffer brand and rejects shared backing stores.
  arrayBufferLength(buffer);
  const length = getLength(input);
  if (length === 0) {
    // The intrinsic validates attached and in-bounds storage before looking up index zero.
    elementAt(input, 0);
  }
  return new constructor(buffer, getOffset(input), length);
}

export function asUint8Array(input) {
  return fixedView(input, 'Uint8Array', ByteArray);
}

export function asUint32Array(input) {
  return fixedView(input, 'Uint32Array', WordArray);
}
