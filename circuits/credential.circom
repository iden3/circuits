/*
# credential.circom

Circuit to check:
- idOwnership: prover is the owner of the identity
- the prover identity is in a ClaimBasic about the identity
- the ClaimBasic is in the MerkleTree of the Issuer identity


                                   +-------------+
    OClaimsTreeRoot+-------------->+             |
                                   |             |
                                   |             |
                                   | idOwnership |
                                   |  Genesis    +<--------------+OMTP
                                   |             |
    OUserPrivateKey+-------------->+             +<--------------+ID+--------+
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
    IssuerRoot+------>+ SMT      +<-----+   |
                      | Poseidon |          |
           MTP+------>+ Verifier +<---------+
                      |          |
                      |          |
                      +----------+

*Note: RevTreeRoot & RootsTreeRoot are needed if is using idOwnership.circom. If is using idOwnershipGenesis.circom, are not needed.
The current implementation of credential.circom uses idOwnershipGenesis.circom.

*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimBasicAboutId.circom";
include "idOwnershipGenesis.circom";

template Credential(nLevels, oNLevels) {
	signal input issuerRoot;
	signal input siblings[nLevels];
	signal input id;

	// signals for idOwnership, all the related signals start with 'o' of 'ownership'
	signal input oUserPrivateKey;
	signal input oSiblings[oNLevels];
	signal input oClaimsTreeRoot;
	// signal input oRevTreeRoot;
	// signal input oRootsTreeRoot;

	component idOwnershipCheck = IdOwnershipGenesis(oNLevels);
	idOwnershipCheck.id <== id;
	idOwnershipCheck.userPrivateKey <== oUserPrivateKey;
	for (var i=0; i<oNLevels; i++) {
		idOwnershipCheck.siblings[i] <== oSiblings[i];
	}
	idOwnershipCheck.claimsTreeRoot <== oClaimsTreeRoot;
	// idOwnershipCheck.revTreeRoot <== oRevTreeRoot;
	// idOwnershipCheck.rootsTreeRoot <== oRootsTreeRoot;

	component claim = BuildClaimBasicAboutId();
	claim.id <== id;
	
	// check ClaimBasic existance in the issuerRoot MerkleTree
	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0;
	smtClaimExists.root <== issuerRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== siblings[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claim.hi;
	smtClaimExists.value <== claim.hv;

	// TODO nullifier
}
