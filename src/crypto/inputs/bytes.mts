// Return a fixed-length view using native typed-array accessors.
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayValues = Uint8Array.prototype.values;

function accessor<T>(prototype: object, key: PropertyKey): (value: unknown) => T {
  const getter = Object.getOwnPropertyDescriptor(prototype, key)?.get;
  if (!getter) throw new Error('Required typed-array accessor missing');
  return (value) => Reflect.apply(getter, value, []) as T;
}

const getType = accessor<string | undefined>(typedArrayPrototype, Symbol.toStringTag);
const getBuffer = accessor<ArrayBufferLike>(typedArrayPrototype, 'buffer');
const getOffset = accessor<number>(typedArrayPrototype, 'byteOffset');
const getLength = accessor<number>(typedArrayPrototype, 'byteLength');
const arrayBufferLength = accessor<number>(ArrayBuffer.prototype, 'byteLength');

export function asUint8Array(input: unknown): Uint8Array {
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
