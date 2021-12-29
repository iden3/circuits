/*
# idState.circom

Circuit to check:
- idOwnership: prover is the owner of the identity (can sign a
challenge with private key, which public key is in a Claim inside the MerkleTree)
- nullifier check
- [in the future] that the identity state transition is correct


                                   +-------------+
PRI_ClaimsTreeRoot+--------------->+             |
                                   |             |
(PRI_RevTreeRoot)+---------------->+             |
                                   | idOwnership |
(PRI_RootsTreeRoot)+-------------->+ BySignature +<--------------+PRI_MTP
                                   |             |
PRI_UserPrivateKey+--------------->+             +<--------------+PUB_ID
                                   +-------------+
                      +----+
              +------>+ != +<----+PUB_OldIdState
              +       +----+
 PUB_NewIdState
              +       +----+
              +------>+ != +<----+0
                      +----+

*/

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "idOwnershipBySignature.circom";

template IdState(nLevels) {
	signal input oldIdState;
	signal input newIdState;

	signal input claimsTreeRoot;
	signal input authClaimMtp[nLevels];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[nLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHv;
    signal input authClaimNonRevMtpAuxHi;

    signal input rootsTreeRoot;

	signal input signatureR8x;
	signal input signatureR8y;
	signal input signatureS;

	// check newIdState is not zero
	component idStateIsNotZero = IsZero();
	idStateIsNotZero.in <== newIdState;
	idStateIsNotZero.out === 0;

	// old & new idState checks
	component oldNewNotEqual = IsEqual();
	oldNewNotEqual.in[0] <== oldIdState;
	oldNewNotEqual.in[1] <== newIdState;
	oldNewNotEqual.out === 0;

    // check id ownership by correct signature of a hash of old state and new state
    component challenge = Poseidon(2);
    challenge.inputs[0] <== oldIdState;
    challenge.inputs[1] <== newIdState;

	component checkIdOwnership = IdOwnershipBySignature(nLevels);

	checkIdOwnership.claimsTreeRoot <== claimsTreeRoot;
	for (var i=0; i<nLevels; i++) { checkIdOwnership.authClaimMtp[i] <== authClaimMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.authClaim[i] <== authClaim[i]; }

	checkIdOwnership.revTreeRoot <== revTreeRoot;
	for (var i=0; i<nLevels; i++) { checkIdOwnership.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
	checkIdOwnership.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
	checkIdOwnership.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
	checkIdOwnership.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

	checkIdOwnership.rootsTreeRoot <== rootsTreeRoot;

    checkIdOwnership.challenge <== challenge.out;
    checkIdOwnership.challengeSignatureR8x <== signatureR8x;
    checkIdOwnership.challengeSignatureR8y <== signatureR8y;
    checkIdOwnership.challengeSignatureS <== signatureS;

	checkIdOwnership.hoIdenState <== oldIdState;
}
