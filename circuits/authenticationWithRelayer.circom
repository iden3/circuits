pragma circom 2.0.0;

include "idOwnershipBySignatureWithRelayer.circom";

template VerifyAuthenticationInformationWithRelayer(IdOwnershipLevels, RelayerLevels) {

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
    signal input id;

    signal input reIdenState;
    signal input hoStateInRelayerClaimMtp[RelayerLevels];
    signal input reProofValidClaimsTreeRoot;
    signal input reProofValidRevTreeRoot;
    signal input reProofValidRootsTreeRoot;

    component checkIdOwnership = IdOwnershipBySignatureWithRelayer(IdOwnershipLevels, RelayerLevels);

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
    
    checkIdOwnership.hoId <== id;

    checkIdOwnership.reIdenState <== reIdenState;
    for (var i=0; i<RelayerLevels; i++) { checkIdOwnership.hoStateInRelayerClaimMtp[i] <== hoStateInRelayerClaimMtp[i]; }
    checkIdOwnership.reProofValidClaimsTreeRoot <== reProofValidClaimsTreeRoot;
    checkIdOwnership.reProofValidRevTreeRoot <== reProofValidRevTreeRoot;
    checkIdOwnership.reProofValidRootsTreeRoot <== reProofValidRootsTreeRoot;
}
