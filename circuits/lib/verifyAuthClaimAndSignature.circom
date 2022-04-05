pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "credential.circom";

template VerifyAuthClaimAndSignature(nLevels) {
	signal input claimsTreeRoot;
	signal input authClaimMtp[nLevels];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[nLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

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

    component claimExists = checkClaimExists(nLevels);
    for (var i=0; i<8; i++) { claimExists.claim[i] <== authClaim[i]; }
	for (var i=0; i<nLevels; i++) { claimExists.claimMTP[i] <== authClaimMtp[i]; }
    claimExists.treeRoot <== claimsTreeRoot;

    component smtClaimNotRevoked = checkClaimNotRevoked(nLevels);
    for (var i=0; i<8; i++) { smtClaimNotRevoked.claim[i] <== claim[i]; }
    for (var i=0; i<nLevels; i++) {
        smtClaimNotRevoked.claimNonRevMTP[i] <== authClaimNonRevMtp[i];
    }
    smtClaimNotRevoked.treeRoot <== revTreeRoot;
    smtClaimNotRevoked.noAux <== authClaimNonRevMtpNoAux;
    smtClaimNotRevoked.auxHi <== authClaimNonRevMtpAuxHi;
    smtClaimNotRevoked.auxHv <== authClaimNonRevMtpAuxHv;

    component sigVerifier = checkDataSignatureWithPubKeyInClaim();
    for (var i=0; i<8; i++) {
        sigVerifier.claim[i] <== authClaim[i];
    }
    sigVerifier.signatureS <== challengeSignatureS;
    sigVerifier.signatureR8X <== challengeSignatureR8x;
    sigVerifier.signatureR8Y <== challengeSignatureR8y;
    sigVerifier.data <== challenge;
}
