/*
Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside the Identity State (in Claim tree)
- the Identity State, in turn, is inside the Relayer State as specific claim
*/

//todo review again

pragma circom 2.0.0;

//todo clean up dependencies
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "buildClaimKeyBBJJ.circom";
include "cutIdState.circom";
include "verifyClaimKeyBBJJ.circom";

template IdOwnershipBySignatureWithRelayer(nLevelsHolder, nLevelsRelayer) {
    signal input hoId;

	signal input claimsTreeRoot;
	signal input authClaimMtp[nLevelsHolder];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[nLevelsHolder];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

	signal input rootsTreeRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    signal input reIdenState;
    signal input hoStateInRelayerClaimMtp[nLevelsRelayer];
	signal input reProofValidClaimsTreeRoot;
	signal input reProofValidRevTreeRoot;
	signal input reProofValidRootsTreeRoot;

    component verifyClaimKeyBBJJ = VerifyClaimKeyBBJJinClaimsTreeRoot(nLevelsHolder);
    for (var i=0; i<8; i++) {
        verifyClaimKeyBBJJ.claim[i] <== authClaim[i];
    }
	for (var i=0; i<nLevelsHolder; i++) {
	    verifyClaimKeyBBJJ.authClaimMtp[i] <== authClaimMtp[i];
    }
	verifyClaimKeyBBJJ.claimsTreeRoot <== claimsTreeRoot;
	verifyClaimKeyBBJJ.revTreeRoot <== revTreeRoot;
	for (var i=0; i<nLevelsHolder; i++) {
	    verifyClaimKeyBBJJ.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i];
    }
	verifyClaimKeyBBJJ.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
	verifyClaimKeyBBJJ.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
	verifyClaimKeyBBJJ.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    // signature verification
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== authClaim[2];
    sigVerifier.Ay <== authClaim[3];
    sigVerifier.S <== challengeSignatureS;
    sigVerifier.R8x <== challengeSignatureR8x;
    sigVerifier.R8y <== challengeSignatureR8y;
    sigVerifier.M <== challenge;

	// get claim for identity state in relayer
	component calcIdState = Poseidon(3);
	calcIdState.inputs[0] <== claimsTreeRoot;
	calcIdState.inputs[1] <== revTreeRoot;
	calcIdState.inputs[2] <== rootsTreeRoot;

    component idenStateInRelayerClaim = getIdenStateInRelayerClaim();
    idenStateInRelayerClaim.id <== hoId;
    idenStateInRelayerClaim.state <== calcIdState.out;

    // check that identity state is included into relayer state
    component claimHiHv = getClaimHiHv();
    for (var i=0; i<8; i++) {
        claimHiHv.claim[i] <== idenStateInRelayerClaim.claim[i];
    }
    
    component isIdentityStateInRelayer = SMTVerifier(nLevelsRelayer);
    isIdentityStateInRelayer.enabled <== 1;
    isIdentityStateInRelayer.fnc <== 0; //inclusion
    isIdentityStateInRelayer.root <== reProofValidClaimsTreeRoot;
    for (var i=0; i<nLevelsRelayer; i++) {
        isIdentityStateInRelayer.siblings[i] <== hoStateInRelayerClaimMtp[i];
    }
    isIdentityStateInRelayer.oldKey <== 0;
    isIdentityStateInRelayer.oldValue <== 0;
    isIdentityStateInRelayer.isOld0 <== 0;
    isIdentityStateInRelayer.key <== claimHiHv.hi;
    isIdentityStateInRelayer.value <== claimHiHv.hv;

	component relayerState = Poseidon(3);
    relayerState.inputs[0] <== reProofValidClaimsTreeRoot;
    relayerState.inputs[1] <== reProofValidRevTreeRoot;
    relayerState.inputs[2] <== reProofValidRootsTreeRoot;

    component isRelayerStateCorrect = IsEqual();
    isRelayerStateCorrect.in[0] <== relayerState.out;
    isRelayerStateCorrect.in[1] <== reIdenState;
    isRelayerStateCorrect.out === 1;
}

template getIdenStateInRelayerClaim() {
    signal input id;
    signal input state;
    signal output claim[8];

    //todo check if need to put all values as in real claim
    claim[0] <== 0;
    claim[1] <== 0;
    claim[2] <== id;
    claim[3] <== 0;
    claim[4] <== 0;
    claim[5] <== 0;
    claim[6] <== state;
    claim[7] <== 0;
}