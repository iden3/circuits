/*
# credential.circom

Circuit to check:
- idOwnership: prover is the owner of the identity
- the prover identity is in a ClaimBasic about the identity
- the ClaimBasic is in the MerkleTree of the Issuer identity


                                   +-------------+
PRI_OClaimsTreeRoot+-------------->+             |
                                   |             |
PRI_ORevTreeRoot+----------------->+             |
                                   | idOwnership |
PRI_ORootsTreeRoot+--------------->+             +<--------------+PRI_OMTP
                                   |             |
PRI_OUserPrivateKey+-------------->+             +<--------------+PRI_ID+----+
                                   +-------------+                           |
                                                                             |
                                    +----------+      +-----------------+    |
   +----+                           |          |      |                 |    |
   | != +<----+0                    | Poseidon +<-----+ buildClaimBasic +<---+
   +--+-+                           |          |      | about ID        |
      ^                             +----------+      |                 |
      |               +----------+     hi   hv        +-----------------+
      |               |          |      +   +
      +               |          |      |   |
PUB_IssuerRoot+------>+ SMT      +<-----+   |
                      | Poseidon |          |
       PRI_MTP+------>+ Verifier +<---------+
                      |          |
                      |          |
                      +----------+


*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimBasicAboutId.circom";
include "idOwnership.circom";

template Credential(nLevels, oNLevels) {
	signal input issuerRoot;
	signal private input mtp[nLevels];
	signal private input id;

	// signals for idOwnership, all the related signals start with 'o' of 'ownership'
	signal private input oUserPrivateKey;
	signal private input oMtp[oNLevels];
	signal private input oClaimsTreeRoot;
	signal private input oRevTreeRoot;
	signal private input oRootsTreeRoot;

	component idOwnershipCheck = IdOwnership(oNLevels);
	idOwnershipCheck.id <== id;
	idOwnershipCheck.userPrivateKey <== oUserPrivateKey;
	for (var i=0; i<oNLevels; i++) {
		idOwnershipCheck.mtp[i] <== oMtp[i];
	}
	idOwnershipCheck.claimsTreeRoot <== oClaimsTreeRoot;
	idOwnershipCheck.revTreeRoot <== oRevTreeRoot;
	idOwnershipCheck.rootsTreeRoot <== oRootsTreeRoot;

	component claim = BuildClaimBasicAboutId();
	claim.id <== id;
	
	// check ClaimBasic existance in the issuerRoot MerkleTree
	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0;
	smtClaimExists.root <== issuerRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== mtp[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claim.hi;
	smtClaimExists.value <== claim.hv;

	// TODO nullifier
}
