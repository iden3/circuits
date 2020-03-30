
/*
# idState.circom

Circuit to check:
- prover is owner of the private key
- prover public key is in a ClaimKAuthBBJJ that is inside the IdState


                      PRI_PbkSign+---+
        +----+                       |
        | == +<------+PRI_PbkAy+--+  |
        +-+--+                    |  |
          ^                       v  v
          |           +-----------+--+------+                          +----------+
          |           |                     |    +----------+          |          +<---------+PRI_MTP
     +----+----+      | buildClaimAuthKBBJJ +--->+          |hi +----->+          |
     | BabyPbk |      |                     |    | Poseidon |          | SMT      |
     +----+----+      +---------------------+    |          |hv +----->+ Poseidon |
          ^                                      +----------+          | Verifier +<---------+PUB_ClaimsTreeRoot
          |                                                            |          |             +
          +              +----------+                                  |          |             |
PRI_UserPrivateKey+----->+          |                                  +----------+             |
                         |          |                                                           |
PUB_OldIdState+--------->+ Poseidon |                                  +---------+              |
                         |          +<----------+        +----+        |         +<-------------+
                         |          |           |        | == +<-------+         |
                         +----+-----+           |        +-+--+        |  ID     +<------------+PUB_RevTreeRoot
                              |                 |          ^           |  State  |
                              v                 |          |           |         +<------------+PUB_RootsTreeRoot
                            +-+--+              |          |           |         |
      PUB_Nullifier+------->+ == |              |          |           +---------+
                            +----+              |          |
                                                |          +                 +----+
                                                +----+PUB_NewIdState+------->+ != +<------+0
                                                                             +----+


*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimAuthKSignBBJJ.circom";

template IdState(nLevels) {
	signal input nullifier; // not used yet
	signal input oldIdState;
	signal private input userPrivateKey;
	signal private input pbkSign;
	signal private input pbkAy;
	signal private input mtp[nLevels];
	signal input claimsTreeRoot;
	signal input revTreeRoot; // not used yet
	signal input rootsTreeRoot; // not used yet
	signal input newIdState;

	// check newIdState is not zero
	component idStateIsZero = IsZero();
	idStateIsZero.in <==newIdState;
	idStateIsZero.out === 0;

	// privateKey & publicKey
	component babyPbk = BabyPbk();
	babyPbk.in <== userPrivateKey;
	
	component pbkCheck = IsEqual();
	pbkCheck.in[0] <== babyPbk.Ay;
	pbkCheck.in[1] <== pbkAy;
	pbkCheck.out === 1;

	// build ClaimAuthKSignBBJJ
	component claim = BuildClaimAuthKSignBBJJ();
	claim.sign <== pbkSign;
	claim.ay <== pbkAy;


	// check claim existance
	component smtClaimExists = SMTVerifier(nLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0;
	smtClaimExists.root <== claimsTreeRoot;
	for (var i=0; i<nLevels; i++) {
		smtClaimExists.siblings[i] <== mtp[i];
	}
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claim.hi;
	smtClaimExists.value <== claim.hv;

	// WIP

	// check claim not revokated (not in this version)

	// nullifier
}
