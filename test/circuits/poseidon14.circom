include "../../node_modules/circomlib/circuits/poseidon.circom";

template PoseidonTest() {
	signal input in[14];
	signal output out;

	component h = Poseidon(14);
	h.inputs[0] <== in[0];
	h.inputs[1] <== in[1];
	h.inputs[2] <== in[2];
	h.inputs[3] <== in[3];
	h.inputs[4] <== in[4];
	h.inputs[5] <== in[5];
	h.inputs[6] <== in[6];
	h.inputs[7] <== in[7];
	h.inputs[8] <== in[8];
	h.inputs[9] <== in[9];
	h.inputs[10] <== in[10];
	h.inputs[11] <== in[11];
	h.inputs[12] <== in[12];
	h.inputs[13] <== in[13];
	//h.inputs[14] <== in[14];
	//h.inputs[15] <== in[15];

	out <== h.out;
}
component main = PoseidonTest();



