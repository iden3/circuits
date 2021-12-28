pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
//include "../node_modules/circomlib/circuits/bitify.circom";
//include "utils.circom";

template BuildClaimKeyBBJJ() {
	var AUTH_SCHEMA_HASH  = 164867201768971999401702181843803888060;

	signal input ax;
	signal input ay;

	signal output hi;
	signal output hv;

//	component e0 = Bits2Num(256);
//	var claimType[256];
//	claimType = bigEndian(CLAIM_TYPE, 128);
//	for (var i=0; i<128; i++) {
//		e0.in[i] <== claimType[i];
//	}
//	for (var i=128; i<256; i++) {
//		e0.in[i] <== 0;
//	}

	// Hi
	component hashHi = Poseidon(4);
	hashHi.inputs[0] <== AUTH_SCHEMA_HASH;
	hashHi.inputs[1] <== 0;
	hashHi.inputs[2] <== ax;
	hashHi.inputs[3] <== ay;
	hi <== hashHi.out;

	// Hv (TODO hardcode hv value as for this claim type will be always the Poseidon hash of 0)
	component hashHv = Poseidon(4);
	hashHv.inputs[0] <== 0;
	hashHv.inputs[1] <== 0;
	hashHv.inputs[2] <== 0;
	hashHv.inputs[3] <== 0;
	hv <== hashHv.out;
}
