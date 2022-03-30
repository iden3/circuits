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
