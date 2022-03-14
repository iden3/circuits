pragma circom 2.0.0;

include "idOwnershipBySignatureWithRelay.circom";

template VerifyAuthenticationInformationWithRelay(IdOwnershipLevels, RelayLevels) {

	signal input claimsTreeRoot;
	signal input authClaimMtp[IdOwnershipLevels];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[IdOwnershipLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHv;
    signal input authClaimNonRevMtpAuxHi;

	signal input rootsTreeRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    //todo check if state should be here
    // we have no constraints for "state" in this circuit, however we introduce "state" input here
    // as it serves as public input which should be the same for prover and verifier
    signal input state;
    signal input userID;

    signal input relayState;
    signal input userStateInRelayClaimMtp[RelayLevels];
    signal input userStateInRelayClaim[8];
    signal input relayProofValidClaimsTreeRoot;
    signal input relayProofValidRevTreeRoot;
    signal input relayProofValidRootsTreeRoot;

    component checkIdOwnership = IdOwnershipBySignatureWithRelay(IdOwnershipLevels, RelayLevels);

	checkIdOwnership.claimsTreeRoot <== claimsTreeRoot;
	for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.authClaimMtp[i] <== authClaimMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.authClaim[i] <== authClaim[i]; }

	checkIdOwnership.revTreeRoot <== revTreeRoot;
	for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
	checkIdOwnership.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
	checkIdOwnership.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
	checkIdOwnership.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    checkIdOwnership.rootsTreeRoot <== rootsTreeRoot;

    checkIdOwnership.challenge <== challenge;
    checkIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== challengeSignatureS;
    
    checkIdOwnership.userID <== userID;

    checkIdOwnership.relayState <== relayState;
    for (var i=0; i<RelayLevels; i++) { checkIdOwnership.userStateInRelayClaimMtp[i] <== userStateInRelayClaimMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.userStateInRelayClaim[i] <== userStateInRelayClaim[i]; }
    checkIdOwnership.relayProofValidClaimsTreeRoot <== relayProofValidClaimsTreeRoot;
    checkIdOwnership.relayProofValidRevTreeRoot <== relayProofValidRevTreeRoot;
    checkIdOwnership.relayProofValidRootsTreeRoot <== relayProofValidRootsTreeRoot;
}
