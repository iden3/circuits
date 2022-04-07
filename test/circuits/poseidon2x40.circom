pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template PoseidonTest(nLevels) {
	signal input in[nLevels];
	signal output out;

    component h[nLevels];

    for (var i=0; i<nLevels; i++) {
        h[i] = Poseidon(2);
        if (i==0) {
            h[i].inputs[0] <== 1;
            h[i].inputs[1] <== in[i];
        } else {
            h[i].inputs[0] <== h[i-1].out;
            h[i].inputs[1] <== in[i];
        }
    }

	out <== h[nLevels-1].out;
}

component main = PoseidonTest(40);
