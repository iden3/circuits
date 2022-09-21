pragma circom 2.0.0;

include "../../circuits/lib/utils/poseidon.util.circom";

template PoseidonTest() {
	signal input in[64];
	signal output out;

	component h = PoseidonUtil(64);
    for(var i = 0; i < 64; i++) {
        h.in[i] <== in[i];
    }

	out <== h.out;
}
component main = PoseidonTest();
