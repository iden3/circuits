/*
Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
- the Identity State, in turn, is inside Relayer state as specific claim
*/

pragma circom 2.0.0;

include "verifyAuthClaim.circom";

template IdOwnershipBySignatureWithRelayer(nLevelsHolder, nLevelsRelayer) {
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

    signal input hoId;

    signal input reIdenState;
    signal input hoStateInRelayerClaimMtp[nLevelsRelayer];
	signal input reProofValidClaimsTreeRoot;
	signal input reProofValidRevTreeRoot;
	signal input reProofValidRootsTreeRoot;

    component verifyAuthClaim = VerifyAuthClaim(nLevelsHolder);
    for (var i=0; i<8; i++) { verifyAuthClaim.authClaim[i] <== authClaim[i]; }
	for (var i=0; i<nLevelsHolder; i++) { verifyAuthClaim.authClaimMtp[i] <== authClaimMtp[i]; }
	verifyAuthClaim.claimsTreeRoot <== claimsTreeRoot;
	verifyAuthClaim.revTreeRoot <== revTreeRoot;
	for (var i=0; i<nLevelsHolder; i++) { verifyAuthClaim.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
	verifyAuthClaim.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
	verifyAuthClaim.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
	verifyAuthClaim.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    verifyAuthClaim.challengeSignatureS <== challengeSignatureS;
    verifyAuthClaim.challengeSignatureR8x <== challengeSignatureR8x;
    verifyAuthClaim.challengeSignatureR8y <== challengeSignatureR8y;
    verifyAuthClaim.challenge <== challenge;

	// get claim for identity state and check that it is included into Relayer's state

	component calcHolderState = getIdenState();
    calcHolderState.claimsTreeRoot <== claimsTreeRoot;
    calcHolderState.revTreeRoot <== revTreeRoot;
    calcHolderState.rootsTreeRoot <== rootsTreeRoot;

    component idenStateInRelayerClaim = getIdenStateInRelayerClaim();
    idenStateInRelayerClaim.id <== hoId;
    idenStateInRelayerClaim.state <== calcHolderState.idenState;

    component claimHiHv = getClaimHiHv();
    for (var i=0; i<8; i++) {
        claimHiHv.claim[i] <== idenStateInRelayerClaim.claim[i];
    }
    
    component checkHolderStateInRelayer = SMTVerifier(nLevelsRelayer);
    checkHolderStateInRelayer.enabled <== 1;
    checkHolderStateInRelayer.fnc <== 0; //inclusion
    checkHolderStateInRelayer.root <== reProofValidClaimsTreeRoot;
    for (var i=0; i<nLevelsRelayer; i++) {
        checkHolderStateInRelayer.siblings[i] <== hoStateInRelayerClaimMtp[i];
    }
    checkHolderStateInRelayer.oldKey <== 0;
    checkHolderStateInRelayer.oldValue <== 0;
    checkHolderStateInRelayer.isOld0 <== 0;
    checkHolderStateInRelayer.key <== claimHiHv.hi;
    checkHolderStateInRelayer.value <== claimHiHv.hv;

	component calcRelayerState = getIdenState();
    calcRelayerState.claimsTreeRoot <== reProofValidClaimsTreeRoot;
    calcRelayerState.revTreeRoot <== reProofValidRevTreeRoot;
    calcRelayerState.rootsTreeRoot <== reProofValidRootsTreeRoot;

    component isRelayerStateCorrect = IsEqual();
    isRelayerStateCorrect.in[0] <== calcRelayerState.idenState;
    isRelayerStateCorrect.in[1] <== reIdenState;
    isRelayerStateCorrect.out === 1;
}

template getIdenStateInRelayerClaim() {
    signal input id;
    signal input state;
    signal output claim[8];

    //todo put correct schema to the claim but not zero
    claim[0] <== 0;
    claim[1] <== 0;
    claim[2] <== id;
    claim[3] <== 0;
    claim[4] <== 0;
    claim[5] <== 0;
    claim[6] <== state;
    claim[7] <== 0;
}