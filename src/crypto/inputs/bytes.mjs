// Return a fixed-length view using native typed-array accessors.
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayValues = Uint8Array.prototype.values;

function accessor(prototype, key) {
  const { get } = Object.getOwnPropertyDescriptor(prototype, key);
  return (value) => Reflect.apply(get, value, []);
}

const getType = accessor(typedArrayPrototype, Symbol.toStringTag);
const getBuffer = accessor(typedArrayPrototype, 'buffer');
const getOffset = accessor(typedArrayPrototype, 'byteOffset');
const getLength = accessor(typedArrayPrototype, 'byteLength');
const arrayBufferLength = accessor(ArrayBuffer.prototype, 'byteLength');

export function asUint8Array(input) {
  if (getType(input) !== 'Uint8Array') throw new TypeError('Expected a Uint8Array');
  const buffer = getBuffer(input);
  // This getter validates the ArrayBuffer brand and rejects shared backing stores.
  arrayBufferLength(buffer);
  const length = getLength(input);
  if (length === 0) {
    // Distinguish an empty array from an out-of-bounds resizable view.
    Reflect.apply(typedArrayValues, input, []);
  }
  return new Uint8Array(buffer, getOffset(input), length);
}
