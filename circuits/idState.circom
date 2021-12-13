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
	signal input id;
	signal input oldIdState;
	signal input newIdState;

	signal input claimsTreeRoot;
	signal input siblingsClaimTree[nLevels];
	signal input claim[8];

	signal input revTreeRoot;
    signal input siblingsRevTree[nLevels];
    signal input revMtpNoAux;
    signal input revMtpAuxHv;
    signal input revMtpAuxHi;

    signal input rootsTreeRoot;

	signal input challenge;
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


    // check id ownership by signature of all the inputs
	component checkIdOwnership = IdOwnershipBySignature(nLevels);
	checkIdOwnership.id <== id;
	checkIdOwnership.hoId <== id;

	checkIdOwnership.claimsTreeRoot <== claimsTreeRoot;
	for (var i=0; i<nLevels; i++) { checkIdOwnership.siblingsClaimTree[i] <== siblingsClaimTree[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.claim[i] <== claim[i]; }

	checkIdOwnership.revTreeRoot <== revTreeRoot;
	for (var i=0; i<nLevels; i++) { checkIdOwnership.siblingsRevTree[i] <== siblingsRevTree[i]; }
	checkIdOwnership.revMtpNoAux <== revMtpNoAux;
	checkIdOwnership.revMtpAuxHv <== revMtpAuxHv;
	checkIdOwnership.revMtpAuxHi <== revMtpAuxHi;

	checkIdOwnership.rootsTreeRoot <== rootsTreeRoot;

    //todo for now it will use the challenge from input but should use the hash of all the inputs
    checkIdOwnership.challenge <== challenge;
    checkIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== challengeSignatureS;

	checkIdOwnership.hoIdenState <== oldIdState;
}
