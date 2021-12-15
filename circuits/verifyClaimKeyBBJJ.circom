pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimKeyBBJJ.circom";
include "credential.circom";

// VerifyClaimKeyBBJJinClaimsTreeRoot:
// circuit to check that claim with the provided public key is in ClaimsTreeRoot
// and its revocation nonce is not in RevTreeRoot
template VerifyClaimKeyBBJJinClaimsTreeRoot(nLevels) {
	signal input claimsTreeRoot;
	signal input siblingsClaimsTree[nLevels];
    signal input claim[8];

	signal input revTreeRoot;
    signal input siblingsRevTree[nLevels];
    signal input revMtpNoAux;
    signal input revMtpAuxHv;
    signal input revMtpAuxHi;

	component claimHiHv = getClaimHiHv();
	for (var i=0; i<8; i++) { claimHiHv.claim[i] <== claim[i]; }

	// check claim existence
	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0;
	smtClaimExists.root <== claimsTreeRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== siblingsClaimsTree[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claimHiHv.hi;
	smtClaimExists.value <== claimHiHv.hv;

    // check claim is not revoked
    component claimRevNonce = getClaimRevNonce();
    for (var i=0; i<8; i++) {
        claimRevNonce.claim[i] <== claim[i];
    }
    component smtClaimNotRevoked = SMTVerifier(nLevels);
    smtClaimNotRevoked.enabled <== 1;
    smtClaimNotRevoked.fnc <== 1; // Non-inclusion
    smtClaimNotRevoked.root <== revTreeRoot;
    for (var i=0; i<nLevels; i++) { smtClaimNotRevoked.siblings[i] <== siblingsRevTree[i]; }
    smtClaimNotRevoked.isOld0 <== revMtpNoAux;
    smtClaimNotRevoked.oldKey <== revMtpAuxHi;
    smtClaimNotRevoked.oldValue <== revMtpAuxHv;
    smtClaimNotRevoked.key <== claimRevNonce.revNonce;
    smtClaimNotRevoked.value <== 0;
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

