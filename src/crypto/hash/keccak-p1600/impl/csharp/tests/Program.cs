using System;
using Abc.Cryptography;

// First XKCP permutation of an all-zero state.
ulong[] expected =
[
    0xf1258f7940e1dde7UL, 0x84d5ccf933c0478aUL, 0xd598261ea65aa9eeUL, 0xbd1547306f80494dUL, 0x8b284e056253d057UL,
    0xff97a42d7f8e6fd4UL, 0x90fee5a0a44647c4UL, 0x8c5bda0cd6192e76UL, 0xad30a6f71b19059cUL, 0x30935ab7d08ffc64UL,
    0xeb5aa93f2317d635UL, 0xa9a6e6260d712103UL, 0x81a57c16dbcf555fUL, 0x43b831cd0347c826UL, 0x01f22f1a11a5569fUL,
    0x05e5635a21d9ae61UL, 0x64befef28cc970f2UL, 0x613670957bc46611UL, 0xb87c5a554fd00ecbUL, 0x8c3ee88a1ccf32c8UL,
    0x940c7922ae3a2614UL, 0x1841f924a2c509e4UL, 0x16f53526e70465c2UL, 0x75f644e97f30a13bUL, 0xeaf1ff7b5ceca249UL,
];
ulong[] actual = new ulong[25];
KeccakSponge.Permute(actual);
if (!actual.AsSpan().SequenceEqual(expected))
    throw new InvalidOperationException("XKCP zero-state permutation mismatch");
Console.WriteLine("permutation_lanes=25");
