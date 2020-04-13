include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./buildClaimKeyBBJJ.circom";

template BuildClaimAuthKSignBBJJ() {
	signal input ax;
	signal input ay;

	signal output hi;
	signal output hv;

	component claim = BuildClaimKeyBBJJ(1);
	claim.ax <== ax;
	claim.ay <== ay;

	hi <== claim.hi;
	hv <== claim.hv;
}
