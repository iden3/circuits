pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimKeyBBJJ.circom";
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

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== authClaim[2]; // Ax should be in indexSlotA
    sigVerifier.Ay <== authClaim[3]; // Ay should be in indexSlotB
    sigVerifier.S <== challengeSignatureS;
    sigVerifier.R8x <== challengeSignatureR8x;
    sigVerifier.R8y <== challengeSignatureR8y;
    sigVerifier.M <== challenge;
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

	component claimHiHv = getClaimHiHv();
	for (var i=0; i<8; i++) { claimHiHv.claim[i] <== claim[i]; }

	// check claim existence
	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0;
	smtClaimExists.root <== claimsTreeRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== authClaimMtp[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claimHiHv.hi;
	smtClaimExists.value <== claimHiHv.hv;

    // check claim is not revoked
    component claimRevNonce = getClaimRevNonce();
    for (var i=0; i<8; i++) {
        claimRevNonce.claim[i] <== claim[i];
    }
    component smtClaimNotRevoked = SMTVerifier(nLevels);
    smtClaimNotRevoked.enabled <== 1;
    smtClaimNotRevoked.fnc <== 1; // Non-inclusion
    smtClaimNotRevoked.root <== revTreeRoot;
    for (var i=0; i<nLevels; i++) { smtClaimNotRevoked.siblings[i] <== authClaimNonRevMtp[i]; }
    smtClaimNotRevoked.isOld0 <== authClaimNonRevMtpNoAux;
    smtClaimNotRevoked.oldKey <== authClaimNonRevMtpAuxHi;
    smtClaimNotRevoked.oldValue <== authClaimNonRevMtpAuxHv;
    smtClaimNotRevoked.key <== claimRevNonce.revNonce;
    smtClaimNotRevoked.value <== 0;
}

