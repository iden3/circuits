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
// todo remove it
//	signal input id;
	signal input oldIdState;
	signal input newIdState;

	signal input claimsTreeRoot;
	signal input siblingsClaimTree[nLevels];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input siblingsRevTree[nLevels];
    signal input revMtpNoAux;
    signal input revMtpAuxHv;
    signal input revMtpAuxHi;

    signal input rootsTreeRoot;

//todo remove it
//	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;


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
    //todo remove it
//	checkIdOwnership.id <== id;
//	checkIdOwnership.hoId <== id;

	checkIdOwnership.claimsTreeRoot <== claimsTreeRoot;
	for (var i=0; i<nLevels; i++) { checkIdOwnership.siblingsClaimTree[i] <== siblingsClaimTree[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.authClaim[i] <== authClaim[i]; }

	checkIdOwnership.revTreeRoot <== revTreeRoot;
	for (var i=0; i<nLevels; i++) { checkIdOwnership.siblingsRevTree[i] <== siblingsRevTree[i]; }
	checkIdOwnership.revMtpNoAux <== revMtpNoAux;
	checkIdOwnership.revMtpAuxHv <== revMtpAuxHv;
	checkIdOwnership.revMtpAuxHi <== revMtpAuxHi;

	checkIdOwnership.rootsTreeRoot <== rootsTreeRoot;

    // it is enough to use old id state as a challenge for security guarantees
    checkIdOwnership.challenge <== challenge.out;
    checkIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== challengeSignatureS;

	checkIdOwnership.hoIdenState <== oldIdState;
}
