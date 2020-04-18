/*
# idOwnershipGenesis.circom

Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside the Genesis Identity State

          OClaimsTreeRoot             0
           +           +              +
           |           |              |
           |           v              v
           |      +----+-----+    +---+------+
           |      | Poseidon |    | Poseidon |
           |      +-------+--+    ++---------+
           |              |        |
           |              v        v
           |             ++--------++
           |             | Poseidon +<--+1 (key)
           |             +----+-----+
           |                  |
           |                  v
           |              +---+---------+
           +------------->+             |
                          |             |
0 (ORevTreeRoot)+-------->+             |
                          | idOwnership |
                          |             +<--------------+OMTP
                          |             |
    OUserPrivateKey+----->+             +<--------------+ID
                          +-------------+


*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "idOwnership.circom";


template IdOwnershipGenesis(nLevels) {
	signal input id;
	signal input userPrivateKey;
	signal input siblings[nLevels];
	signal input claimsTreeRoot;

	component hi = Poseidon(1, 6, 8, 57);
	hi.inputs[0] <== claimsTreeRoot;
	component hv = Poseidon(1, 6, 8, 57);
	hv.inputs[0] <== 0;
	component rootsTreeRoot = Poseidon(3, 6, 8, 57);
	rootsTreeRoot.inputs[0] <== hi.out;
	rootsTreeRoot.inputs[1] <== hv.out;
	rootsTreeRoot.inputs[2] <== 1;


	component idOwnershipCheck = IdOwnership(nLevels);
	idOwnershipCheck.id <== id;
	idOwnershipCheck.userPrivateKey <== userPrivateKey;
	for (var i=0; i<nLevels; i++) {
		idOwnershipCheck.siblings[i] <== siblings[i];
	}
	idOwnershipCheck.claimsTreeRoot <== claimsTreeRoot;
	idOwnershipCheck.revTreeRoot <== 0;
	idOwnershipCheck.rootsTreeRoot <== rootsTreeRoot.out;
}
