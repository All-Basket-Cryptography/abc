import { testEcdsaP256 } from '../../../../providers/ecmascript/conformance.mjs';
import * as implementation from './ecdsa_p256.mts';

testEcdsaP256(implementation);
