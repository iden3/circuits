/*
Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
- the Identity State, in turn, is inside Relay state as specific claim
*/

pragma circom 2.0.0;

include "verifyAuthClaim.circom";

template IdOwnershipBySignatureWithRelay(nLevelsUser, nLevelsRelay) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

	signal input claimsTreeRoot;
	signal input authClaimMtp[nLevelsUser];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[nLevelsUser];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

	signal input rootsTreeRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    signal input userID;

    signal input relayState;
    signal input userStateInRelayClaimMtp[nLevelsRelay];
    signal input userStateInRelayClaim[8];
	signal input relayProofValidClaimsTreeRoot;
	signal input relayProofValidRevTreeRoot;
	signal input relayProofValidRootsTreeRoot;

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> End Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    component verifyAuthClaim = VerifyAuthClaim(nLevelsUser);
    for (var i=0; i<8; i++) { verifyAuthClaim.authClaim[i] <== authClaim[i]; }
	for (var i=0; i<nLevelsUser; i++) { verifyAuthClaim.authClaimMtp[i] <== authClaimMtp[i]; }
	verifyAuthClaim.claimsTreeRoot <== claimsTreeRoot;
	verifyAuthClaim.revTreeRoot <== revTreeRoot;
	for (var i=0; i<nLevelsUser; i++) { verifyAuthClaim.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
	verifyAuthClaim.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
	verifyAuthClaim.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
	verifyAuthClaim.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    verifyAuthClaim.challengeSignatureS <== challengeSignatureS;
    verifyAuthClaim.challengeSignatureR8x <== challengeSignatureR8x;
    verifyAuthClaim.challengeSignatureR8y <== challengeSignatureR8y;
    verifyAuthClaim.challenge <== challenge;

	// get claim for identity state and check that it is included into Relay's state

	component calcUserState = getIdenState();
    calcUserState.claimsTreeRoot <== claimsTreeRoot;
    calcUserState.revTreeRoot <== revTreeRoot;
    calcUserState.rootsTreeRoot <== rootsTreeRoot;

    calcUserState.idenState === userStateInRelayClaim[6];

	component header = getClaimHeader();
	for (var i=0; i<8; i++) { header.claim[i] <== userStateInRelayClaim[i]; }

	component subjectOtherIden = getClaimSubjectOtherIden(0);
	for (var i=0; i<8; i++) { subjectOtherIden.claim[i] <== userStateInRelayClaim[i]; }
	for (var i=0; i<32; i++) { subjectOtherIden.claimFlags[i] <== header.claimFlags[i]; }

    userID === subjectOtherIden.id;

    component claimHiHv = getClaimHiHv();
    for (var i=0; i<8; i++) {
        claimHiHv.claim[i] <== userStateInRelayClaim[i];
    }

    // Check that StatinInRelayClaim is in Relay state
    component checkUserStateInRelay = SMTVerifier(nLevelsRelay);
    checkUserStateInRelay.enabled <== 1;
    checkUserStateInRelay.fnc <== 0; //inclusion
    checkUserStateInRelay.root <== relayProofValidClaimsTreeRoot;
    for (var i=0; i<nLevelsRelay; i++) {
        checkUserStateInRelay.siblings[i] <== userStateInRelayClaimMtp[i];
    }
    checkUserStateInRelay.oldKey <== 0;
    checkUserStateInRelay.oldValue <== 0;
    checkUserStateInRelay.isOld0 <== 0;
    checkUserStateInRelay.key <== claimHiHv.hi;
    checkUserStateInRelay.value <== claimHiHv.hv;

	component calcRelayState = getIdenState();
    calcRelayState.claimsTreeRoot <== relayProofValidClaimsTreeRoot;
    calcRelayState.revTreeRoot <== relayProofValidRevTreeRoot;
    calcRelayState.rootsTreeRoot <== relayProofValidRootsTreeRoot;

    component isRelayStateCorrect = IsEqual();
    isRelayStateCorrect.in[0] <== calcRelayState.idenState;
    isRelayStateCorrect.in[1] <== relayState;
    isRelayStateCorrect.out === 1;
}
