include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./utils.circom";

template BuildClaimBasicAboutId() {
	var CLAIM_TYPE  = 0;
	var VERSION = 0;

	signal input id;

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

	// Hi
	component hashHi = Poseidon(2, 6, 8, 57);
	hashHi.inputs[0] <== e0.out;
	hashHi.inputs[1] <== id;
	hi <== hashHi.out;

	// Hv
	component hashHv = Poseidon(0, 6, 8, 57);
	hv <== hashHv.out;
}
