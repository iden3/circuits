/*
# idOwnershipBySignature.circom

Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside the Genesis Identity State

                                                 +----------+
+---------------------+    +----------+          |          +<---------+MTP
|                     |    |          |hi +----->+          |
|  buildClaimKeyBBJJ  +--->+ Poseidon |          | SMT      |
|     (keyType 1)     |    |          |hv +----->+ Poseidon |
+----------+----------+    +----------+          | Verifier +<---------+ClaimsTreeRoot
           ^                                     |          |             +
           |                                     |          |             |
           +                                     +----------+             |
     UserPublicKey                                                        |
                                                 +---------+              |
                                    +----+       |         +<-------------+
                                    | == +<------+         |
                                    +-+--+       |  ID     +<------------+RevTreeRoot
                                      ^          |  State  |
                                      |          |         +<------------+RootsTreeRoot
                                      |          |         |
                                      |          +---------+
                                      |
                                      +                +----+
                                     ID+-------------->+ != +<------+0
                                                       +----+


*/

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "buildClaimKeyBBJJ.circom";
include "cutIdState.circom";
include "verifyClaimKeyBBJJ.circom";

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

    component verifyClaimKeyBBJJ = VerifyClaimKeyBBJJinClaimsTreeRoot(nLevels);
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

	// check identity state
	// note that the Type & Checksum on this version is not verified
	component calcIdState = Poseidon(3);
	calcIdState.inputs[0] <== claimsTreeRoot;
	calcIdState.inputs[1] <== revTreeRoot;
	calcIdState.inputs[2] <== rootsTreeRoot;

	component checkIdState = IsEqual();
	checkIdState.in[0] <== calcIdState.out;
	checkIdState.in[1] <== hoIdenState;
	checkIdState.out === 1;

    // signature verification
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== authClaim[2];
    sigVerifier.Ay <== authClaim[3];
    sigVerifier.S <== challengeSignatureS;
    sigVerifier.R8x <== challengeSignatureR8x;
    sigVerifier.R8y <== challengeSignatureR8y;
    sigVerifier.M <== challenge;
}
