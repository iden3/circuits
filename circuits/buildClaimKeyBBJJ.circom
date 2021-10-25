include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "utils.circom";

template BuildClaimKeyBBJJ(keytype) {
	var CLAIM_TYPE  = 1;
	var VERSION = 0;

	signal input ax;
	signal input ay;
	// signal input revnonce;

	signal output hi;
	signal output hv;

	component e0 = Bits2Num(256);
	var claimType[128];
	claimType = bigEndian(CLAIM_TYPE, 128);
	for (var i=0; i<128; i++) {
		e0.in[i] <== claimType[i];
	}
	for (var i=128; i<256; i++) {
		e0.in[i] <== 0;
	}
	
	component e1 = Bits2Num(256);
	var keytypeBE[128];
	keytypeBE = bigEndian(keytype, 128);
	for (var i=0; i<128; i++) {
		e1.in[i] <== keytypeBE[i];
	}
	for (var i=128; i<256; i++) {
		e1.in[i] <== 0;
	}

	// Hi
	component hashHi = Poseidon(4);
	hashHi.inputs[0] <== e0.out;
	hashHi.inputs[1] <== e1.out;
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
