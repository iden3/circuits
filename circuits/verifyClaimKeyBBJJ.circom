pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimKeyBBJJ.circom";

// VerifyClaimKeyBBJJinClaimsTreeRoot - Circuit to check that claim with the provided public key is in ClaimsTreeRoot
template VerifyClaimKeyBBJJinClaimsTreeRoot(nLevels) {
	signal input BBJAx;
	signal input BBJAy;
	signal input siblings[nLevels];
	signal input claimsTreeRoot;

	// build ClaimKeyBBJJ
	component claim = BuildClaimKeyBBJJ(1);
	claim.ax <== BBJAx;
	claim.ay <== BBJAy;

	// check claim existence
	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0;
	smtClaimExists.root <== claimsTreeRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== siblings[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claim.hi;
	smtClaimExists.value <== claim.hv;
}

// VerifyClaimKeyBBJJinClaimsTreeRoot - Circuit to check that claim with the provided public key is in ClaimsTreeRoot
template VerifyClaimKeyBBJJinIdState(nLevels) {
	signal input BBJAx;
	signal input BBJAy;
	signal input siblings[nLevels];
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;
	signal input idState;

	// build ClaimKeyBBJJ
	component verifyClaimKeyBBJJinClaimsTreeRoot = VerifyClaimKeyBBJJinClaimsTreeRoot(nLevels);
	verifyClaimKeyBBJJinClaimsTreeRoot.BBJAx <== BBJAx;
	verifyClaimKeyBBJJinClaimsTreeRoot.BBJAy <== BBJAy;
    for (var i=0; i<nLevels; i++) {
        verifyClaimKeyBBJJinClaimsTreeRoot.siblings[i] <== siblings[i];
    }
    verifyClaimKeyBBJJinClaimsTreeRoot.claimsTreeRoot <== claimsTreeRoot;

    component calcIdState = Poseidon(3);
    calcIdState.inputs[0] <== claimsTreeRoot;
    calcIdState.inputs[1] <== revTreeRoot;
    calcIdState.inputs[2] <== rootsTreeRoot;

    calcIdState.out === idState;

}

