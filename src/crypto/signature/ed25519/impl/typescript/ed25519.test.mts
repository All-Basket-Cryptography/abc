import { testEd25519 } from '../../../../providers/ecmascript/conformance.mjs';
import * as implementation from './ed25519.mts';

testEd25519(implementation);
