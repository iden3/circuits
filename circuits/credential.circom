/*
# credential.circom

Circuit to check that the prover have received a claim from an issuer.
The circuit checks:
- idOwnersip: prover is the owner of the identity (knows the private key inside a claim inside the MerkleTree)
- the claim subject == prover identity
- the claim exists in the MerkleTree of the issuer
- the proof is valid (and not revoked) for the given issuer-id-state

*/

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/mux3.circom";
include "./idOwnershipBySignature.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// getClaimSubjectOtherIden checks that a claim Subject is OtherIden and
// outputs the identity within.  Parameter index is bool:  0 if SubjectPos is
// Index, 1 if SubjectPos is Value.
template getClaimSubjectOtherIden(index) {
	signal input claim[8];
	signal input claimFlags[32]; // claimFlags must be parsed from the claim

	signal output id;

	// Assert that claim subject is OtherIden
	// flags[0:2] == [0, 1]: Subject == OtherIden
	claimFlags[0] === 0;
	claimFlags[1] === 1;
	// flags[2] == 0 / 1: SubjectPos == Index / Value
	claimFlags[2] === index;

	if (index == 0) {
		id <== claim[0*4 + 1];
	} else {
		id <== claim[1*4 + 1];
	}
}

// getClaimHeader gets the header of a claim, outputing the claimType as an
// integer and the claimFlags as a bit array.
template getClaimHeader() {
	signal input claim[8];

	signal output claimType;
	signal output claimFlags[32];

 	component i0Bits = Num2Bits(256);
	i0Bits.in <== claim[0];

	component claimTypeNum = Bits2Num(128);

	for (var i=0; i<128; i++) {
		claimTypeNum.in[i] <== i0Bits.out[i];
	}
	claimType <== claimTypeNum.out;

	for (var i=0; i<32; i++) {
		claimFlags[i] <== i0Bits.out[128 + i];
	}
}

// getClaimSchema gets the schema of a claim
template getClaimSchema() {
	signal input claim[8];

	signal output schema;

 	component i0Bits = Num2Bits(256);
	i0Bits.in <== claim[0];

	component schemaNum = Bits2Num(128);

	for (var i=0; i<128; i++) {
		schemaNum.in[i] <== i0Bits.out[i];
	}
	schema <== schemaNum.out;
}

// getClaimRevNonce gets the revocation nonce out of a claim outputing it as an integer.
template getClaimRevNonce() {
	signal input claim[8];

	signal output revNonce;

	component claimRevNonce = Bits2Num(32);

 	component v0Bits = Num2Bits(256);
	v0Bits.in <== claim[4];
	for (var i=0; i<32; i++) {
		claimRevNonce.in[i] <== v0Bits.out[i];
	}
	revNonce <== claimRevNonce.out;
}

//  getClaimHiHv calculates the hashes Hi and Hv of a claim (to be used as
//  key,value in an SMT).
template getClaimHiHv() {
	signal input claim[8];

	signal output hi;
	signal output hv;

	component hashHi = Poseidon(4);
	for (var i=0; i<4; i++) {
		hashHi.inputs[i] <== claim[i];
	}
	hi <== hashHi.out;

	component hashHv = Poseidon(4);
	for (var i=0; i<4; i++) {
		hashHv.inputs[i] <== claim[4 + i];
	}
	hv <== hashHv.out;
}

//  getClaimHash calculates the hash a claim
template getClaimHash() {
	signal input claim[8];
	signal output hash;
	signal output hi;
	signal output hv;

    component hihv = getClaimHiHv();
	for (var i=0; i<8; i++) {
		hihv.claim[i] <== claim[i];
	}

	component hashAll = Poseidon(2);
	hashAll.inputs[0] <== hihv.hi;
	hashAll.inputs[1] <== hihv.hv;
	hash <== hashAll.out;
	hi <== hihv.hi;
	hv <== hihv.hv;
}

// getIdenState caclulates the Identity state out of the claims tree root,
// revocations tree root and roots tree root.
template getIdenState() {
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;

	signal output idenState;

	component calcIdState = Poseidon(3);
	calcIdState.inputs[0] <== claimsTreeRoot;
	calcIdState.inputs[1] <== revTreeRoot;
	calcIdState.inputs[2] <== rootsTreeRoot;

	idenState <== calcIdState.out;
}

// getRevNonceNoVerHiHv calculates the hashes Hi and Hv of the leaf used in the
// revocations tree, out of a revocation nonce, to be used as key, value in an
// SMT.
template getRevNonceNoVerHiHv() {
	signal input revNonce;
	// signal input version;

	signal output hi;
	signal output hv;

	component hashHi = Poseidon(6);
	hashHi.inputs[0] <== revNonce;
	for (var i=1; i<6; i++) {
		hashHi.inputs[i] <== 0;
	}
	hi <== hashHi.out;

	component hashHv = Poseidon(6);
	hashHv.inputs[0] <== 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
	for (var i=1; i<6; i++) {
		hashHv.inputs[i] <== 0;
	}
	hv <== hashHv.out;

	// hv = Poseidon([0xffff_ffff, 0, 0, 0, 0)
	//hv <== Poseidon([0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, 0, 0, 0, 0, 0])
	//hv <== 17142353815121200339963760108352696118925531835836661574604762966243856573359;
	//hv <== 8137207316649344643315856769015464323293372071975540252804619894838929375565; // new from go
}

// getRootHiHv calculates the hashes Hi and Hv of the leaf used in the roots
// tree, out of a root, to be used as a key, value in an SMT.
template getRootHiHv() {
	signal input root;

	signal output hi;
	signal output hv;

	component hashHi = Poseidon(6);
	hashHi.inputs[0] <== root;
	for (var i=1; i<6; i++) {
		hashHi.inputs[i] <== 0;
	}
	hi <== hashHi.out;

	component hashHv = Poseidon(6);
	for (var i=0; i<6; i++) {
		hashHv.inputs[i] <== 0;
	}
	hv <== hashHv.out;

	//hv <== Poseidon([0, 0, 0, 0, 0, 0])
	//hv <== 951383894958571821976060584138905353883650994872035011055912076785884444545;
	//hv <== 14408838593220040598588012778523101864903887657864399481915450526643617223637; // new from go
}


// proveCredentialOwnership proves ownership of an identity (found in `claim[1]`) which
// is contained in a claim (`claim`) issued by an identity that has a recent
// identity state (`isIdenState`), while proving that the claim has not been
// revoked as of the recent identity state.
template proveCredentialOwnership(IdOwnershipLevels, IssuerLevels) {
	// A Prove that the claim has subject OtherIden, and take the subject identity.
	signal input claim[8];

	// B. holder proof that private key signing the challenge is in his identity state and not revoked
    signal input hoId;
    signal input hoIdenState;

    signal input hoClaimsTreeRoot;
    signal input hoAuthClaimMtp[IdOwnershipLevels];
    signal input hoAuthClaim[8];

    signal input hoRevTreeRoot;
    signal input hoAuthClaimNonRevMtp[IdOwnershipLevels];
    signal input hoAuthClaimNonRevMtpNoAux;
    signal input hoAuthClaimNonRevMtpAuxHv;
    signal input hoAuthClaimNonRevMtpAuxHi;

    signal input hoRootsTreeRoot;

    signal input hoChallenge;
    signal input hoChallengeSignatureR8x;
    signal input hoChallengeSignatureR8y;
    signal input hoChallengeSignatureS;

	// C. issuer proof of claim existence
	signal input isProofExistClaimsTreeRoot;
	signal input isProofExistMtp[IssuerLevels];

	// D. issuer proof of claim validity
	signal input isProofValidRevTreeRoot;
	signal input isProofValidNonRevMtp[IssuerLevels];
	signal input isProofValidNonRevMtpNoAux;
	signal input isProofValidNonRevMtpAuxHi;
	signal input isProofValidNonRevMtpAuxHv;

	signal input isProofValidClaimsTreeRoot;

	signal input isProofValidRootsTreeRoot;

	// E. issuer proof of Root (ExistClaimsTreeRoot)
	signal input isProofRootMtp[IssuerLevels];

	// F. issuer recent idenState
	signal input isIdenState;

	//
	// A. Prove that the claim has subject OtherIden, and take the subject identity.
	//
	component header = getClaimHeader();
	for (var i=0; i<8; i++) { header.claim[i] <== claim[i]; }
	// out: header.claimType
	// out: header.claimFlags[32]

	component subjectOtherIden = getClaimSubjectOtherIden(0);
	for (var i=0; i<8; i++) { subjectOtherIden.claim[i] <== claim[i]; }
	for (var i=0; i<32; i++) { subjectOtherIden.claimFlags[i] <== header.claimFlags[i]; }
	// out: subjectOtherIden.id

	component claimRevNonce = getClaimRevNonce();
	for (var i=0; i<8; i++) { claimRevNonce.claim[i] <== claim[i]; }
	// out: claimRevNonce.revNonce

	component claimHiHv = getClaimHiHv();
	for (var i=0; i<8; i++) { claimHiHv.claim[i] <== claim[i]; }
	// out: claimHiHv.hi
	// out: claimHiHv.hv

    component checkHoId = IsEqual();
    checkHoId.in[0] <== subjectOtherIden.id;
    checkHoId.in[1] <== hoId;
    checkHoId.out === 1;

	//
	// B. Proof that private key signing the challenge is in holder identity state and not revoked
	//

	component checkIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);
	checkIdOwnership.hoIdenState <== hoIdenState;
	checkIdOwnership.claimsTreeRoot <== hoClaimsTreeRoot;
	for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.authClaimMtp[i] <== hoAuthClaimMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.authClaim[i] <== hoAuthClaim[i]; }
	checkIdOwnership.revTreeRoot <== hoRevTreeRoot;
	for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.authClaimNonRevMtp[i] <== hoAuthClaimNonRevMtp[i]; }
	checkIdOwnership.authClaimNonRevMtpNoAux <== hoAuthClaimNonRevMtpNoAux;
	checkIdOwnership.authClaimNonRevMtpAuxHi <== hoAuthClaimNonRevMtpAuxHv;
	checkIdOwnership.authClaimNonRevMtpAuxHv <== hoAuthClaimNonRevMtpAuxHi;

	checkIdOwnership.rootsTreeRoot <== hoRootsTreeRoot;

    checkIdOwnership.challenge <== hoChallenge;
    checkIdOwnership.challengeSignatureR8x <== hoChallengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== hoChallengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== hoChallengeSignatureS;

	//
	// C. Claim proof of existence (isProofExist)
	//
	component smtClaimExists = SMTVerifier(IssuerLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0; // Inclusion
	smtClaimExists.root <== isProofExistClaimsTreeRoot;
	for (var i=0; i<IssuerLevels; i++) { smtClaimExists.siblings[i] <== isProofExistMtp[i]; }
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claimHiHv.hi;
	smtClaimExists.value <== claimHiHv.hv;

	//
	// D. Claim proof of non revocation (validity)
	//

	component smtClaimValid = SMTVerifier(IssuerLevels);
	smtClaimValid.enabled <== 1;
	smtClaimValid.fnc <== 1; // Non-inclusion
	smtClaimValid.root <== isProofValidRevTreeRoot;
	for (var i=0; i<IssuerLevels; i++) { smtClaimValid.siblings[i] <== isProofValidNonRevMtp[i]; }
	smtClaimValid.oldKey <== isProofValidNonRevMtpAuxHi;
	smtClaimValid.oldValue <== isProofValidNonRevMtpAuxHv;
	smtClaimValid.isOld0 <== isProofValidNonRevMtpNoAux;
	smtClaimValid.key <== claimRevNonce.revNonce;
	smtClaimValid.value <== 0;


	//
	// E. Claim proof of root
	//
	component smtRootValid = SMTVerifier(IssuerLevels);
	smtRootValid.enabled <== 1;
	smtRootValid.fnc <== 0; // Inclusion
	smtRootValid.root <== isProofValidRootsTreeRoot;
	for (var i=0; i<IssuerLevels; i++) { smtRootValid.siblings[i] <== isProofRootMtp[i]; }
	smtRootValid.oldKey <== 0;
	smtRootValid.oldValue <== 0;
	smtRootValid.isOld0 <== 0;
	smtRootValid.key <== isProofExistClaimsTreeRoot;
	smtRootValid.value <== 0;

	//
	// F. Verify ValidIdenState == isIdenState
	//
	component isProofValidIdenState = getIdenState();
	isProofValidIdenState.claimsTreeRoot <== isProofValidClaimsTreeRoot;
	isProofValidIdenState.revTreeRoot <== isProofValidRevTreeRoot;
	isProofValidIdenState.rootsTreeRoot <== isProofValidRootsTreeRoot;
	// out: isProofValidIdenState.idenState

	isProofValidIdenState.idenState === isIdenState;
}






// verifyCredentialSubject verifies that claim is issued to a specified identity
template verifyCredentialSubject() {
	signal input claim[8];
	signal input id;

	//
	// A. Prove that the claim has subject OtherIden, and take the subject identity.
	//
	component header = getClaimHeader();
	for (var i=0; i<8; i++) { header.claim[i] <== claim[i]; }
	// out: header.claimType
	// out: header.claimFlags[32]

    // TODO: add reading SubjectPos from claim (0 = index, 1 = value) and providing it to the following component
	component subjectOtherIden = getClaimSubjectOtherIden(0);
	for (var i=0; i<8; i++) { subjectOtherIden.claim[i] <== claim[i]; }
	for (var i=0; i<32; i++) { subjectOtherIden.claimFlags[i] <== header.claimFlags[i]; }
	// out: subjectOtherIden.id

    subjectOtherIden.id === id;
}

// verifyCredentialSchema verifies that claim matches provided schema
template verifyCredentialSchema() {
	signal input claim[8];
	signal input schema;

	component claimSchema = getClaimSchema();
	for (var i=0; i<8; i++) { claimSchema.claim[i] <== claim[i]; }

	claimSchema.schema === schema;
}

// verifyCredentialNotRevoked verifies that claim is not included into the revocation tree
// TODO: how do we get all of these params and why do we need them at all?
template verifyCredentialNotRevoked(IssuerLevels) {
	signal input claim[8];

	// D. issuer proof of claim validity
	signal input isProofValidNonRevMtp[IssuerLevels];
	signal input isProofValidNonRevMtpNoAux;
	signal input isProofValidNonRevMtpAuxHi;
	signal input isProofValidNonRevMtpAuxHv;
	signal input isProofValidRevTreeRoot;


	component claimRevNonce = getClaimRevNonce();
	for (var i=0; i<8; i++) { claimRevNonce.claim[i] <== claim[i]; }
	// out: claimRevNonce.revNonce

	//
	// D. Claim proof of non revocation (validity)
	//
	component revNonceHiHv = getRevNonceNoVerHiHv();
	revNonceHiHv.revNonce <== claimRevNonce.revNonce;

	component smtClaimValid = SMTVerifier(IssuerLevels);
	smtClaimValid.enabled <== 1;
	smtClaimValid.fnc <== 1; // Non-inclusion
	smtClaimValid.root <== isProofValidRevTreeRoot;
	for (var i=0; i<IssuerLevels; i++) { smtClaimValid.siblings[i] <== isProofValidNonRevMtp[i]; }
	smtClaimValid.oldKey <== isProofValidNonRevMtpAuxHi;
	smtClaimValid.oldValue <== isProofValidNonRevMtpAuxHv;
	smtClaimValid.isOld0 <==  isProofValidNonRevMtpNoAux;
	smtClaimValid.key <== revNonceHiHv.hi;
	smtClaimValid.value <== 0;
}

// verifyCredentialMtp verifies that claim is issued by the issuer and included into the claim tree root
template verifyCredentialMtp(IssuerLevels) {
	signal input claim[8];

	// C. issuer proof of claim existence
	// TODO: rename signals
	signal input isProofExistMtp[IssuerLevels]; // issuerClaimMtp
	signal input isProofExistClaimsTreeRoot;    // issuerClaimTreeRoot
	// signal input isProofExistRevTreeRoot;    // issuerRevTreeRoot
	// signal input isProofExistRootsTreeRoot;  // issuerRootsTreeRoot

	component claimHiHv = getClaimHiHv();
	for (var i=0; i<8; i++) { claimHiHv.claim[i] <== claim[i]; }
	// out: claimHiHv.hi
	// out: claimHiHv.hv

	//
	// C. Claim proof of existence (isProofExist)
	//
	component smtClaimExists = SMTVerifier(IssuerLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0; // Inclusion
	smtClaimExists.root <== isProofExistClaimsTreeRoot;
	for (var i=0; i<IssuerLevels; i++) { smtClaimExists.siblings[i] <== isProofExistMtp[i]; }
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== claimHiHv.hi;
	smtClaimExists.value <== claimHiHv.hv;
}

// verifyCredentialMtp verifies that claim is issued by the issuer and included into the claim tree root
template verifyCredentialMtpHiHv(IssuerLevels) {
	signal input hi;
	signal input hv;

	signal input isProofExistMtp[IssuerLevels]; // issuerClaimMtp
	signal input isProofExistClaimsTreeRoot;    // issuerClaimTreeRoot
	// signal input isProofExistRevTreeRoot;    // issuerRevTreeRoot
	// signal input isProofExistRootsTreeRoot;  // issuerRootsTreeRoot

	component smtClaimExists = SMTVerifier(IssuerLevels);
	smtClaimExists.enabled <== 1;
	smtClaimExists.fnc <== 0; // Inclusion
	smtClaimExists.root <== isProofExistClaimsTreeRoot;
	for (var i=0; i<IssuerLevels; i++) { smtClaimExists.siblings[i] <== isProofExistMtp[i]; }
	smtClaimExists.oldKey <== 0;
	smtClaimExists.oldValue <== 0;
	smtClaimExists.isOld0 <== 0;
	smtClaimExists.key <== hi;
	smtClaimExists.value <== hv;
}

// verifyClaimsTreeRoot verifies that claim is issued by the issuer and included into the claim tree root
// TODO: what is this check doing? Is it checking inclusion of claim tree root to the roots tree for indirect identities?
// TODO: Or it should be included to the roots tree for direct identities too?
template verifyClaimsTreeRoot(IssuerLevels) {
	signal input isProofExistClaimsTreeRoot;    // issuerClaimTreeRoot
	signal input isProofValidRootsTreeRoot;

	// E. issuer proof of Root (ExistClaimsTreeRoot)
	signal input isProofRootMtp[IssuerLevels];

	//
	// E. Claim proof of root
	//
	component rootHiHv = getRootHiHv();
	rootHiHv.root <== isProofExistClaimsTreeRoot;

	component smtRootValid = SMTVerifier(IssuerLevels);
	smtRootValid.enabled <== 1;
	smtRootValid.fnc <== 0; // Inclusion
	smtRootValid.root <== isProofValidRootsTreeRoot;
	for (var i=0; i<IssuerLevels; i++) { smtRootValid.siblings[i] <== isProofRootMtp[i]; }
	smtRootValid.oldKey <== 0;
	smtRootValid.oldValue <== 0;
	smtRootValid.isOld0 <== 0;
	smtRootValid.key <== rootHiHv.hi;
	smtRootValid.value <== rootHiHv.hv;
}

// verifyCredentialExistence verifies that claim is issued by the issuer
// is contained in a claim (`claim`) issued by an identity that has a recent
// identity state (`isIdenState`), while proving that the claim has not been
// revoked as of the recent identity state.
template verifyIdenStateMatchesRoots() {
	signal input isProofValidClaimsTreeRoot;
	signal input isProofValidRevTreeRoot;
	signal input isProofValidRootsTreeRoot;
	signal input isIdenState;

	//
	// F. Verify ValidIdenState == isIdenState
	//
	component isProofValidIdenState = getIdenState();
	isProofValidIdenState.claimsTreeRoot <== isProofValidClaimsTreeRoot;
	isProofValidIdenState.revTreeRoot <== isProofValidRevTreeRoot;
	isProofValidIdenState.rootsTreeRoot <== isProofValidRootsTreeRoot;
	// out: isProofValidIdenState.idenState

	isProofValidIdenState.idenState === isIdenState;
}

// verifyClaimIssuance verifies that claim is issued by the issuer and not revoked
template verifyClaimIssuanceNonRev(IssuerLevels) {
	signal input claim[8];
	signal input claimIssuanceMtp[IssuerLevels];
	signal input claimIssuanceClaimsTreeRoot;
	signal input claimIssuanceRevTreeRoot;
	signal input claimIssuanceRootsTreeRoot;
	signal input claimIssuanceIdenState;

	signal input claimNonRevMtp[IssuerLevels];
	signal input claimNonRevMtpNoAux;
	signal input claimNonRevMtpAuxHi;
	signal input claimNonRevMtpAuxHv;
	signal input claimNonRevIssuerClaimsTreeRoot;
	signal input claimNonRevIssuerRevTreeRoot;
	signal input claimNonRevIssuerRootsTreeRoot;
	signal input claimNonRevIssuerState;

    // verify country claim is included in claims tree root
    component claimIssuanceCheck = verifyCredentialMtp(IssuerLevels);
    for (var i=0; i<8; i++) { claimIssuanceCheck.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) { claimIssuanceCheck.isProofExistMtp[i] <== claimIssuanceMtp[i]; }
    claimIssuanceCheck.isProofExistClaimsTreeRoot <== claimIssuanceClaimsTreeRoot;

    // verify issuer state includes country claim
    component verifyClaimIssuanceIdenState = verifyIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.isProofValidClaimsTreeRoot <== claimIssuanceClaimsTreeRoot;
    verifyClaimIssuanceIdenState.isProofValidRevTreeRoot <== claimIssuanceRevTreeRoot;
    verifyClaimIssuanceIdenState.isProofValidRootsTreeRoot <== claimIssuanceRootsTreeRoot;
    verifyClaimIssuanceIdenState.isIdenState <== claimIssuanceIdenState;

    // check non-revocation proof for claim
    component verifyClaimNotRevoked = verifyCredentialNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) {
        verifyClaimNotRevoked.isProofValidNonRevMtp[i] <== claimNonRevMtp[i];
    }
    verifyClaimNotRevoked.isProofValidNonRevMtpNoAux <== claimNonRevMtpNoAux;
    verifyClaimNotRevoked.isProofValidNonRevMtpAuxHi <== claimNonRevMtpAuxHi;
    verifyClaimNotRevoked.isProofValidNonRevMtpAuxHv <== claimNonRevMtpAuxHv;
    verifyClaimNotRevoked.isProofValidRevTreeRoot <== claimNonRevIssuerRevTreeRoot;

    // check issuer state matches for non-revocation proof
    component verifyClaimNonRevIssuerState = verifyIdenStateMatchesRoots();
    verifyClaimNonRevIssuerState.isProofValidClaimsTreeRoot <== claimNonRevIssuerClaimsTreeRoot;
    verifyClaimNonRevIssuerState.isProofValidRevTreeRoot <== claimNonRevIssuerRevTreeRoot;
    verifyClaimNonRevIssuerState.isProofValidRootsTreeRoot <== claimNonRevIssuerRootsTreeRoot;
    verifyClaimNonRevIssuerState.isIdenState <== claimNonRevIssuerState;
}

// verifyClaimSignature verifies that claim is signed with the provided public key
template verifyClaimSignature() {
	signal input claim[8];
	signal input sigR8x;
	signal input sigR8y;
	signal input sigS;
	signal input pubKeyX;
	signal input pubKeyY;

    component hash = getClaimHash();
    for (var i=0; i<8; i++) { hash.claim[i] <== claim[i]; }

    // signature verification
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;

    sigVerifier.Ax <== pubKeyX;
    sigVerifier.Ay <== pubKeyY;

    sigVerifier.S <== sigS;
    sigVerifier.R8x <== sigR8x;
    sigVerifier.R8y <== sigR8y;

    sigVerifier.M <== hash.hash;
}

// verifyClaimIssuanceNonRevBySignature verifies that claim is signed with the provided public key,
// claim is not revoked and revocation root is in issuer's state
template verifyClaimIssuanceNonRevBySignature(IssuerLevels) {
	signal input claim[8];
	signal input id;
	signal input sigR8x;
	signal input sigR8y;
	signal input sigS;
	signal input pubKeyX;
	signal input pubKeyY;
	signal input claimNonRevMtp[IssuerLevels];
	signal input claimNonRevMtpNoAux;
	signal input claimNonRevMtpAuxHi;
	signal input claimNonRevMtpAuxHv;
	signal input claimNonRevIssuerClaimsTreeRoot;
	signal input claimNonRevIssuerRevTreeRoot;
	signal input claimNonRevIssuerRootsTreeRoot;
	signal input claimNonRevIssuerState;

    // check claim is issued to provided identity
    component claimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== claim[i]; }
    claimIdCheck.id <== id;

    // check claim signature
    component claimSignature = verifyClaimSignature();
    for (var i=0; i<8; i++) { claimSignature.claim[i] <== claim[i]; }
	claimSignature.sigR8x <== sigR8x;
	claimSignature.sigR8y <== sigR8y;
	claimSignature.sigS <== sigS;
	claimSignature.pubKeyX <== pubKeyX;
	claimSignature.pubKeyY <== pubKeyY;

    // check non-revocation proof for claim
    component verifyClaimNotRevoked = verifyCredentialNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) {
        verifyClaimNotRevoked.isProofValidNonRevMtp[i] <== claimNonRevMtp[i];
    }
    verifyClaimNotRevoked.isProofValidNonRevMtpNoAux <== claimNonRevMtpNoAux;
    verifyClaimNotRevoked.isProofValidNonRevMtpAuxHi <== claimNonRevMtpAuxHi;
    verifyClaimNotRevoked.isProofValidNonRevMtpAuxHv <== claimNonRevMtpAuxHv;
    verifyClaimNotRevoked.isProofValidRevTreeRoot <== claimNonRevIssuerRevTreeRoot;

    // check issuer state matches for non-revocation proof
    component verifyClaimNonRevIssuerState = verifyIdenStateMatchesRoots();
    verifyClaimNonRevIssuerState.isProofValidClaimsTreeRoot <== claimNonRevIssuerClaimsTreeRoot;
    verifyClaimNonRevIssuerState.isProofValidRevTreeRoot <== claimNonRevIssuerRevTreeRoot;
    verifyClaimNonRevIssuerState.isProofValidRootsTreeRoot <== claimNonRevIssuerRootsTreeRoot;
    verifyClaimNonRevIssuerState.isIdenState <== claimNonRevIssuerState;
}

// getValueByIndex select slot from claim by given index
template getValueByIndex(){
  signal input claim[8];
  signal input index;
  signal output value; // value from the selected slot claim[index]

  component mux = Mux3();
  component n2b = Num2Bits(8);
  n2b.in <== index;
  for(var i=0;i<8;i++){
    mux.c[i] <== claim[i];
  }

  mux.s[0] <== n2b.out[0];
  mux.s[1] <== n2b.out[1];
  mux.s[2] <== n2b.out[2];

  value <== mux.out;
}

// verify that the claim has expiration time and it is less then timestamp
template verifyExpirationTime() {
	signal input claim[8];
	signal input timestamp;

	//
	// A. Prove that the claim has expiration time and it is less then time stamp.
	//
	component header = getClaimHeader();
	for (var i=0; i<8; i++) { header.claim[i] <== claim[i]; }
	// out: header.claimType
	// out: header.claimFlags[32]


  component expirationComp =  getClaimExpiration();
  for (var i=0; i<8; i++) { expirationComp.claim[i] <== claim[i]; }

  component lt = LessEqThan(252); // timestamp < expirationComp.expiration
  lt.in[0] <== timestamp;
  lt.in[1] <== expirationComp.expiration;

  component res = Mux1();
  res.c[0] <== 1;
  res.c[1] <== lt.out;
  res.s <== header.claimFlags[3];

  res.out === 1;
}

// getClaimExpiration extract expiration date from claim
template getClaimExpiration() {
	signal input claim[8];

	signal output expiration;

	component expirationBits = Bits2Num(64);

 	component v0Bits = Num2Bits(256);
	v0Bits.in <== claim[4];
	for (var i=0; i<64; i++) {
		expirationBits.in[i] <== v0Bits.out[i+64];
	}
	expiration <== expirationBits.out;
}