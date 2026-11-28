import { testEd25519 } from '../../../../providers/ecmascript/conformance.mjs';
import * as implementation from './ed25519.mjs';

testEd25519(implementation);
