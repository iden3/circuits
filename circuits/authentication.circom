pragma circom 2.0.0;

include "idOwnershipBySignature.circom";

template VerifyAuthenticationInformation(IdOwnershipLevels) {

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
    
    checkIdOwnership.hoIdenState <== state;
}
