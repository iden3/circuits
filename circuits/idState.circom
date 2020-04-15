/*
# idState.circom

Circuit to check:
- idOwnership: prover is the owner of the identity
- nullifier check
- [in the future] that the identity state transition is correct


                                   +-------------+
PRI_ClaimsTreeRoot+--------------->+             |
                                   |             |
PRI_RevTreeRoot+------------------>+             |
                                   | idOwnership |
PRI_RootsTreeRoot+---------------->+             +<--------------+PRI_MTP
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
include "idOwnership.circom";

template IdState(nLevels) {
	signal input id;
	signal input nullifier;
	signal input oldIdState;
	signal private input userPrivateKey;
	signal private input mtp[nLevels];
	signal private input claimsTreeRoot;
	signal private input revTreeRoot;
	signal private input rootsTreeRoot;
	signal private input newIdState;

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
	for (var i=0; i<nLevels; i++) {
		checkIdOwnership.mtp[i] <== mtp[i];
	}
	checkIdOwnership.claimsTreeRoot <== claimsTreeRoot;
	checkIdOwnership.revTreeRoot <== revTreeRoot;
	checkIdOwnership.rootsTreeRoot <== rootsTreeRoot;
}
