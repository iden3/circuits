include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./utils.circom";

template BuildClaimAuthKSignBBJJ() {
	var CLAIM_TYPE  = 1;
	var VERSION = 0;

	signal input sign;
	signal input ay;
	// signal input revnonce;

	signal output hi;
	signal output hv;

	component e0 = Bits2Num(256);
	var claimType = bigEndian(CLAIM_TYPE, 64);
	for (var i=0; i<64; i++) {
		e0.in[i] <== claimType[i];
	}
	for (var i=64; i<256; i++) {
		e0.in[i] <== 0;
	}

	component e1 = Bits2Num(256);
	component signBits = Num2Bits(8);
	signBits.in <== sign;
	for (var i=0; i<8; i++) {
		e1.in[i] <== signBits.out[i];
	}
	for (var i=8; i<256; i++) {
		e1.in[i] <== 0;
	}

	// Hi
	component hashHi = Poseidon(6, 6, 8, 57);
	hashHi.inputs[0] <== e0.out;
	hashHi.inputs[1] <== e1.out;
	hashHi.inputs[2] <== ay;
	hashHi.inputs[3] <== 0;
	hashHi.inputs[4] <== 0;
	hashHi.inputs[5] <== 0;
	hi <== hashHi.out;

	// Hv (TODO hardcode hv value as for this claim type will be always the Poseidon hash of 0)
	component hashHv = Poseidon(0, 6, 8, 57);
	hv <== hashHv.out;
}
