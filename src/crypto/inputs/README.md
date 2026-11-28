# ECMAScript cryptographic byte and word views

The common input boundary reads the intrinsic typed-array tag, buffer,
offset and element count. It admits `Uint8Array` or `Uint32Array` as
requested, requires an attached, in-bounds ordinary `ArrayBuffer`, and
returns a fixed-length view over the established range. This preserves
buffer identity and gives the callee normal accessors even for views from
another realm or a subclass. Detached, out-of-bounds and shared storage
raise `TypeError`. For a zero element count, the captured intrinsic
`at` operation distinguishes a valid empty span from an invalid view.
[ECMAScript typed-array objects](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-typedarray-objects)

Lean checks the range model for fixed and length-tracking inputs. It proves
that the empty-view test leads to exactly the admitted contract, that
successful offsets and extents stay within the backing range, and that
the captured fixed range remains valid after growth. The model takes the
intrinsic slot behavior and stability during synchronous capture as
premises. Runtime tests cover the actual JavaScript and TypeScript entry
points on Node 24.12.0. [View model](TypedArrayView.lean) · [20-profile contract suite](../../../tools/compatibility/ecmascript-views)

```sh
node --test src/crypto/inputs/bytes.test.mjs
lean -DwarningAsError=true src/crypto/inputs/TypedArrayView.lean
```
