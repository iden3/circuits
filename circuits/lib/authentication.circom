pragma circom 2.0.0;

include "idOwnershipBySignature.circom";

template VerifyAuthentication(IdOwnershipLevels) {

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
	
    signal input state;
    // we have no constraints for "id" in this circuit, however we introduce "id" input here
    // as it serves as public input which should be the same for prover and verifier
    signal input id;

    component checkIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);

	checkIdOwnership.userClaimsTreeRoot <== claimsTreeRoot;
	for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.userAuthClaimMtp[i] <== authClaimMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.userAuthClaim[i] <== authClaim[i]; }

	checkIdOwnership.userRevTreeRoot <== revTreeRoot;
	for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.userAuthClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
	checkIdOwnership.userAuthClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
	checkIdOwnership.userAuthClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
	checkIdOwnership.userAuthClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    checkIdOwnership.userRootsTreeRoot <== rootsTreeRoot;

    checkIdOwnership.challenge <== challenge;
    checkIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== challengeSignatureS;
    
    checkIdOwnership.userState <== state;
}
