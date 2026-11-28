// Return a fixed-length view using native typed-array accessors.
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const ByteArray = Uint8Array;
const WordArray = Uint32Array;
const elementAt = Function.prototype.call.bind(Uint8Array.prototype.at);

function accessor<T>(prototype: object, key: PropertyKey): (value: unknown) => T {
  const getter = Object.getOwnPropertyDescriptor(prototype, key)?.get;
  if (!getter) throw new Error('Required typed-array accessor missing');
  return Function.prototype.call.bind(getter);
}

const getType = accessor<string | undefined>(typedArrayPrototype, Symbol.toStringTag);
const getBuffer = accessor<ArrayBufferLike>(typedArrayPrototype, 'buffer');
const getOffset = accessor<number>(typedArrayPrototype, 'byteOffset');
const getLength = accessor<number>(typedArrayPrototype, 'length');
const arrayBufferLength = accessor<number>(ArrayBuffer.prototype, 'byteLength');

function fixedView<T>(input: unknown, type: string,
  constructor: new (buffer: ArrayBufferLike, offset: number, length: number) => T): T {
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

export function asUint8Array(input: unknown): Uint8Array {
  return fixedView(input, 'Uint8Array', ByteArray);
}

export function asUint32Array(input: unknown): Uint32Array {
  return fixedView(input, 'Uint32Array', WordArray);
}
