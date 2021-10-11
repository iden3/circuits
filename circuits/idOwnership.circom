/*
# idOwnership.circom

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
           |                                     +----------+             |
      +----+----+                                                         |
      | pvk2pbk |                                +---------+              |
      +----+----+                   +----+       |         +<-------------+
           ^                        | == +<------+         |
           |                        +-+--+       |  ID     +<------------+RevTreeRoot
           |                          ^          |  State  |
           +                          |          |         +<------------+RootsTreeRoot
     UserPrivateKey                   |          |         |
                                      |          +---------+
                                      |
                                      +                +----+
                                     ID+-------------->+ != +<------+0
                                                       +----+


*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "verifyClaimKeyBBJJ.circom";
include "cutIdState.circom";

template IdOwnership(nLevels) {
	signal input id;
	signal input userPrivateKey;
	signal input siblings[nLevels];
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;

	// privateKey & publicKey
	component babyPbk = BabyPbk();
	babyPbk.in <== userPrivateKey;
	
    component verifyClaimKeyBBJJ = VerifyClaimKeyBBJJinClaimsTreeRoot(nLevels)
	verifyClaimKeyBBJJ.BBJAx <== babyPbk.Ax;
	verifyClaimKeyBBJJ.BBJAy <== babyPbk.Ay;
	for (var i=0; i<nLevels; i++) {
		verifyClaimKeyBBJJ.siblings[i] <== siblings[i];
	}
	verifyClaimKeyBBJJ.claimsTreeRoot <== claimsTreeRoot;

	// check identity state
	// note that the Type & Checksum on this version is not verified
	component calcIdState = Poseidon(3);
	calcIdState.inputs[0] <== claimsTreeRoot;
	calcIdState.inputs[1] <== revTreeRoot;
	calcIdState.inputs[2] <== rootsTreeRoot;

	component calcCutState = cutState();
	calcCutState.in <== calcIdState.out;

	component calcCutId = cutId();
	calcCutId.in <== id;

	component checkIdState = IsEqual();
	checkIdState.in[0] <== calcCutState.out;
	checkIdState.in[1] <== calcCutId.out;
	checkIdState.out === 1;

	// TODO: check claim not revoked
}
