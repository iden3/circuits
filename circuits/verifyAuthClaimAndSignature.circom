pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
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

    component verifyClaimKeyBBJJ = VerifyClaimKeyBBJJinState(nLevels);
    for (var i=0; i<8; i++) {
        verifyClaimKeyBBJJ.claim[i] <== authClaim[i];
    }
    for (var i=0; i<nLevels; i++) {
        verifyClaimKeyBBJJ.authClaimMtp[i] <== authClaimMtp[i];
    }
    verifyClaimKeyBBJJ.claimsTreeRoot <== claimsTreeRoot;
    verifyClaimKeyBBJJ.revTreeRoot <== revTreeRoot;
    for (var i=0; i<nLevels; i++) {
        verifyClaimKeyBBJJ.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i];
    }
    verifyClaimKeyBBJJ.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
    verifyClaimKeyBBJJ.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
    verifyClaimKeyBBJJ.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    component sigVerifier = checkDataSignatureWithPubKeyInClaim();
    for (var i=0; i<8; i++) {
        sigVerifier.claim[i] <== authClaim[i];
    }
    sigVerifier.signatureS <== challengeSignatureS;
    sigVerifier.signatureR8X <== challengeSignatureR8x;
    sigVerifier.signatureR8Y <== challengeSignatureR8y;
    sigVerifier.data <== challenge;
}

// circuit to check that claim with the provided public key is in ClaimsTreeRoot
// and its revocation nonce is not in RevTreeRoot
template VerifyClaimKeyBBJJinState(nLevels) {
	signal input claimsTreeRoot;
	signal input authClaimMtp[nLevels];
    signal input claim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[nLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHv;
    signal input authClaimNonRevMtpAuxHi;

    component claimExists = checkClaimExists(nLevels);
    for (var i=0; i<8; i++) { claimExists.claim[i] <== claim[i]; }
	for (var i=0; i<nLevels; i++) { claimExists.claimMTP[i] <== authClaimMtp[i]; }
    claimExists.treeRoot <== claimsTreeRoot;

    // check claim is not revoked
    component smtClaimNotRevoked = checkClaimNotRevoked(nLevels);
    for (var i=0; i<8; i++) { smtClaimNotRevoked.claim[i] <== claim[i]; }
    for (var i=0; i<nLevels; i++) {
        smtClaimNotRevoked.claimNonRevMTP[i] <== authClaimNonRevMtp[i];
    }
    smtClaimNotRevoked.treeRoot <== revTreeRoot;
    smtClaimNotRevoked.noAux <== authClaimNonRevMtpNoAux;
    smtClaimNotRevoked.auxHi <== authClaimNonRevMtpAuxHi;
    smtClaimNotRevoked.auxHv <== authClaimNonRevMtpAuxHv;
}

