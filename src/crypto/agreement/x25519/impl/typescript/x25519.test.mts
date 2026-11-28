import { testX25519 } from '../../../../providers/ecmascript/conformance.mjs';
import * as implementation from './x25519.mts';

testX25519(implementation);
