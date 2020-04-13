/*
# idState.circom

Circuit to check:
- idOwnership: prover is the owner of the identity
- nullifier check
- [in the future] that the identity state transition is correct

                                   +-------------+
PUB_ClaimsTreeRoot+--------------->+             +<--------------+PRI_PbkSign
                                   |             |
PUB_RevTreeRoot+------------------>+             +<--------------+PRI_PbkAy
                                   | idOwnership |
PUB_RootsTreeRoot+---------------->+             +<--------------+PRI_MTP
                                   |             |
PRI_UserPrivateKey+--------------->+             +<--------------+PUB_ID
         +                         +-------------+                  +
         |                                                          |
         |                                                          |
         |               +----------+                               |
         +-------------->+          |                               |
                         |          +<------------------------------+
PUB_OldIdState+--------->+ Poseidon |
                         |          |          +----+
PUB_NewIdState+--------->+          +--------->+ == +<------+PUB_Nullifier
                         +----------+          +----+




*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimAuthKSignBBJJ.circom";
include "idOwnership.circom";

template IdState(nLevels) {
	signal input id;
	signal input nullifier;
	signal input oldIdState;
	signal private input userPrivateKey;
	signal private input pbkAx;
	signal private input pbkAy;
	signal private input mtp[nLevels];
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;
	signal input newIdState;

	// check newIdState is not zero
	component idStateIsNotZero = IsZero();
	idStateIsNotZero.in <==newIdState;
	idStateIsNotZero.out === 0;

	// nullifier checks
	component nullifierHash = Poseidon(3, 6, 8, 57);
	nullifierHash.inputs[0] <== userPrivateKey;
	nullifierHash.inputs[1] <== oldIdState;
	nullifierHash.inputs[2] <== newIdState;
	
	component checkNullifier = IsEqual();
	checkNullifier.in[0] <== nullifierHash.out;
	checkNullifier.in[1] <== nullifier;
	checkNullifier.out === 1;

	component checkIdOwnership = IdOwnership(nLevels);
	checkIdOwnership.id <== id;
	checkIdOwnership.userPrivateKey <== userPrivateKey;
	checkIdOwnership.pbkAx <== pbkAx;
	checkIdOwnership.pbkAy <== pbkAy;
	for (var i=0; i<nLevels; i++) {
		checkIdOwnership.mtp[i] <== mtp[i];
	}
	checkIdOwnership.claimsTreeRoot <== claimsTreeRoot;
	checkIdOwnership.revTreeRoot <== revTreeRoot;
	checkIdOwnership.rootsTreeRoot <== rootsTreeRoot;
}
