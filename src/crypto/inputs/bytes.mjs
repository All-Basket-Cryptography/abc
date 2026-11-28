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

function fixedView(input, type, constructor, bytesPerElement) {
  if (getType(input) !== type) throw new TypeError(`Expected a ${type}`);
  const buffer = getBuffer(input);
  // This getter validates the ArrayBuffer brand and rejects shared backing stores.
  arrayBufferLength(buffer);
  const length = getLength(input);
  if (length === 0) {
    // Distinguish an empty array from an out-of-bounds resizable view.
    Reflect.apply(typedArrayValues, input, []);
  }
  return new constructor(buffer, getOffset(input), length / bytesPerElement);
}

export function asUint8Array(input) {
  return fixedView(input, 'Uint8Array', Uint8Array, 1);
}

export function asUint32Array(input) {
  return fixedView(input, 'Uint32Array', Uint32Array, 4);
}
