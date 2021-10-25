/*
# idState.circom

Circuit to check:
- idOwnership: prover is the owner of the identity (knows the private key inside a Claim inside the MerkleTree)
- nullifier check
- [in the future] that the identity state transition is correct


                                   +-------------+
PRI_ClaimsTreeRoot+--------------->+             |
                                   |             |
(PRI_RevTreeRoot)+---------------->+             |
                                   | idOwnership |
(PRI_RootsTreeRoot)+-------------->+   Genesis   +<--------------+PRI_MTP
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


*Note: (RevTreeRoot) & (RootsTreeRoot) are needed if is using idOwnership.circom. If is using idOwnershipGenesis.circom, are not needed.
The current implementation of idState.circom uses idOwnershipGenesis.circom.



*/

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
/* include "idOwnership.circom"; */
include "idOwnershipGenesis.circom";

template IdState(nLevels) {
	signal input id;
	signal input oldIdState;
	signal input userPrivateKey;
	signal input siblings[nLevels];
	signal input claimsTreeRoot;
	/* signal input revTreeRoot; */
	/* signal input rootsTreeRoot; */
	signal input newIdState;

	// check newIdState is not zero
	component idStateIsNotZero = IsZero();
	idStateIsNotZero.in <== newIdState;
	idStateIsNotZero.out === 0;

	// old & new idState checks
	component oldNewNotEqual = IsEqual();
	oldNewNotEqual.in[0] <== oldIdState;
	oldNewNotEqual.in[1] <== newIdState;
	oldNewNotEqual.out === 0;

	component checkIdOwnership = IdOwnershipGenesis(nLevels);
	checkIdOwnership.id <== id;
	checkIdOwnership.userPrivateKey <== userPrivateKey;
	for (var i=0; i<nLevels; i++) {
		checkIdOwnership.siblings[i] <== siblings[i];
	}
	checkIdOwnership.claimsTreeRoot <== claimsTreeRoot;
	/* checkIdOwnership.revTreeRoot <== revTreeRoot; */
	/* checkIdOwnership.rootsTreeRoot <== rootsTreeRoot; */
}
