/*
Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
- the Identity State, in turn, is inside Relay state as specific claim
*/

pragma circom 2.0.0;

include "verifyAuthClaim.circom";

template IdOwnershipBySignatureWithRelay(nLevelsHolder, nLevelsRelay) {
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
    signal input hoStateInRelayClaimMtp[nLevelsRelay];
    signal input hoStateInRelayClaim[8];
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

	// get claim for identity state and check that it is included into Relay's state

	component calcHolderState = getIdenState();
    calcHolderState.claimsTreeRoot <== claimsTreeRoot;
    calcHolderState.revTreeRoot <== revTreeRoot;
    calcHolderState.rootsTreeRoot <== rootsTreeRoot;

    calcHolderState.idenState === hoStateInRelayClaim[6];

	component header = getClaimHeader();
	for (var i=0; i<8; i++) { header.claim[i] <== hoStateInRelayClaim[i]; }

	component subjectOtherIden = getClaimSubjectOtherIden(0);
	for (var i=0; i<8; i++) { subjectOtherIden.claim[i] <== hoStateInRelayClaim[i]; }
	for (var i=0; i<32; i++) { subjectOtherIden.claimFlags[i] <== header.claimFlags[i]; }

    hoId === subjectOtherIden.id;

    component claimHiHv = getClaimHiHv();
    for (var i=0; i<8; i++) {
        claimHiHv.claim[i] <== hoStateInRelayClaim[i];
    }

    // Check that StatinInRelayClaim is in Relay state
    component checkHolderStateInRelay = SMTVerifier(nLevelsRelay);
    checkHolderStateInRelay.enabled <== 1;
    checkHolderStateInRelay.fnc <== 0; //inclusion
    checkHolderStateInRelay.root <== reProofValidClaimsTreeRoot;
    for (var i=0; i<nLevelsRelay; i++) {
        checkHolderStateInRelay.siblings[i] <== hoStateInRelayClaimMtp[i];
    }
    checkHolderStateInRelay.oldKey <== 0;
    checkHolderStateInRelay.oldValue <== 0;
    checkHolderStateInRelay.isOld0 <== 0;
    checkHolderStateInRelay.key <== claimHiHv.hi;
    checkHolderStateInRelay.value <== claimHiHv.hv;

	component calcRelayState = getIdenState();
    calcRelayState.claimsTreeRoot <== reProofValidClaimsTreeRoot;
    calcRelayState.revTreeRoot <== reProofValidRevTreeRoot;
    calcRelayState.rootsTreeRoot <== reProofValidRootsTreeRoot;

    component isRelayStateCorrect = IsEqual();
    isRelayStateCorrect.in[0] <== calcRelayState.idenState;
    isRelayStateCorrect.in[1] <== reIdenState;
    isRelayStateCorrect.out === 1;
}
