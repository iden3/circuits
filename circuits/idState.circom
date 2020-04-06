
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
PUB_NewIdState+--------->+          |           |        | == +<-------+         |
                         +----+-----+           |        +-+--+        |  ID     +<------------+PUB_RevTreeRoot
                              |                 |          ^           |  State  |
                              v                 |          |           |         +<------------+PUB_RootsTreeRoot
                            +-+--+              |          |           |         |
      PUB_Nullifier+------->+ == |              |          |           +---------+
                            +----+              |          |
                                                |          +                 +----+
                                                +------+PUB_ID+------------->+ != +<------+0
                                                                             +----+



*/

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "buildClaimAuthKSignBBJJ.circom";


template cutId() {
	signal input in;
	signal output out;

	component idBits = Num2Bits(256);
	idBits.in <== in;

	component cutted = Bits2Num(256-16-16-8);
	for (var i=16; i<256-16-8; i++) {
		cutted.in[i-16] <== idBits.out[i];
	}
	out <== cutted.out
}

template cutState() {
	signal input in;
	signal output out;

	component stateBits = Num2Bits(256);
	stateBits.in <== in;

	component cutted = Bits2Num(256-16-16-8);
	for (var i=0; i<256-16-16-8; i++) {
		cutted.in[i] <== stateBits.out[i+16+16+8];
	}
	out <== cutted.out
}

template IdState(nLevels) {
	signal input id;
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

	// check identity state
	// note that the Type & Checksum on this version is not verified
	component calcIdState = Poseidon(3, 6, 8, 57);
	calcIdState.inputs[0] <== claimsTreeRoot;
	calcIdState.inputs[1] <== revTreeRoot;
	calcIdState.inputs[2] <== rootsTreeRoot;

	component cuttedState = cutState();
	cuttedState.in <== calcIdState.out;
	
	component cuttedId = cutId();
	cuttedId.in <== id;

	component checkIdState = IsEqual();
	checkIdState.in[0] <== cuttedState.out;
	checkIdState.in[1] <== cuttedId.out;
	checkIdState.out === 1;

	// WIP

	// check claim not revokated (not in this version)

	// nullifier checks
	component nullifierHash = Poseidon(3, 6, 8, 57);
	nullifierHash.inputs[0] <== userPrivateKey;
	nullifierHash.inputs[1] <== oldIdState;
	nullifierHash.inputs[2] <== newIdState;
	
	component checkNullifier = IsEqual();
	checkNullifier.in[0] <== nullifierHash.out;
	checkNullifier.in[1] <== nullifier;
	checkNullifier.out === 1;
}
