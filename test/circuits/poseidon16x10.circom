pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template PoseidonTest(nLevels) {
	signal input in[16*nLevels];
	signal output out;

    component h[nLevels];

    for (var i=0; i<nLevels; i++) {
        h[i] = Poseidon(16);
        for (var j=0; j<16; j++) {
            h[i].inputs[j] <== in[i*16+j];
        }
    }
	out <== h[nLevels-1].out;
}

component main = PoseidonTest(10);
