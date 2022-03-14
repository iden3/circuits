/*
# idOwnershipBySignature.circom

Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
*/

pragma circom 2.0.0;

include "verifyAuthClaim.circom";
include "credential.circom";

template IdOwnershipBySignature(nLevels) {
    signal input hoIdenState;

	signal input claimsTreeRoot;
	signal input authClaimMtp[nLevels];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[nLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

	signal input rootsTreeRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;


    var AUTH_SCHEMA_HASH  = 269270088098491255471307608775043319525;
    component verifyAuthSchema  = verifyCredentialSchema();
    for (var i=0; i<8; i++) {
            verifyAuthSchema.claim[i] <== authClaim[i];
    }
    verifyAuthSchema.schema <== AUTH_SCHEMA_HASH;

    component verifyAuthClaim = VerifyAuthClaim(nLevels);
    for (var i=0; i<8; i++) { verifyAuthClaim.authClaim[i] <== authClaim[i]; }
	for (var i=0; i<nLevels; i++) { verifyAuthClaim.authClaimMtp[i] <== authClaimMtp[i]; }
	verifyAuthClaim.claimsTreeRoot <== claimsTreeRoot;
	verifyAuthClaim.revTreeRoot <== revTreeRoot;
	for (var i=0; i<nLevels; i++) { verifyAuthClaim.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
	verifyAuthClaim.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
	verifyAuthClaim.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
	verifyAuthClaim.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    verifyAuthClaim.challengeSignatureS <== challengeSignatureS;
    verifyAuthClaim.challengeSignatureR8x <== challengeSignatureR8x;
    verifyAuthClaim.challengeSignatureR8y <== challengeSignatureR8y;
    verifyAuthClaim.challenge <== challenge;

	component calcHolderState = getIdenState();
    calcHolderState.claimsTreeRoot <== claimsTreeRoot;
    calcHolderState.revTreeRoot <== revTreeRoot;
    calcHolderState.rootsTreeRoot <== rootsTreeRoot;

    component checkHolderState = IsEqual();
    checkHolderState.in[0] <== calcHolderState.idenState;
    checkHolderState.in[1] <== hoIdenState;
    checkHolderState.out === 1;
}
