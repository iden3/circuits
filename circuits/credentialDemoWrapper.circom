include "./credential.circom"

template proveCredentialOwnershipDemo(IdOwnershipLevels, IssuerLevels) {
	var idOwnershipLevels = IdOwnershipLevels + 1;
	var issuerLevels = IssuerLevels + 1;

	// A
	signal input claim[8];

	// B. holder proof of claimKOp in the genesis
	signal private input hoKOpSk;
	signal private input hoClaimKOpMtp[idOwnershipLevels];
	signal private input hoClaimKOpClaimsTreeRoot;
	// signal input hoClaimKOpRevTreeRoot;
	// signal input hoClaimKOpRootsTreeRoot;

	// C. issuer proof of claim existence
	signal private input isProofExistMtp[issuerLevels];
	signal private input isProofExistClaimsTreeRoot;
	// signal input isProofExistRevTreeRoot;
	// signal input isProofExistRootsTreeRoot;

	// D. issuer proof of claim validity
	signal private input isProofValidNotRevMtp[issuerLevels];
	signal private input isProofValidNotRevMtpNoAux;
	signal private input isProofValidNotRevMtpAuxHi;
	signal private input isProofValidNotRevMtpAuxHv;
	signal private input isProofValidClaimsTreeRoot;
	signal private input isProofValidRevTreeRoot;
	signal private input isProofValidRootsTreeRoot;

	// E. issuer proof of Root (ExistClaimsTreeRoot)
	signal private input isProofRootMtp[issuerLevels];

	// F. issuer recent idenState
	signal input isIdenState;

	component credentialOwnership = proveCredentialOwnership(IdOwnershipLevels, IssuerLevels);
	for (var i=0; i<8; i++) { credentialOwnership.claim[i] <== claim[i]; }
	credentialOwnership.hoKOpSk <== hoKOpSk;
	for (var i=0; i<idOwnershipLevels; i++) { credentialOwnership.hoClaimKOpMtp[i] <== hoClaimKOpMtp[i]; }
	credentialOwnership.hoClaimKOpClaimsTreeRoot <== hoClaimKOpClaimsTreeRoot;
	for (var i=0; i<issuerLevels; i++) { credentialOwnership.isProofExistMtp[i] <== isProofExistMtp[i]; }
	credentialOwnership.isProofExistClaimsTreeRoot <== isProofExistClaimsTreeRoot;
	for (var i=0; i<issuerLevels; i++) { credentialOwnership.isProofValidNotRevMtp[i] <== isProofValidNotRevMtp[i]; }
	credentialOwnership.isProofValidNotRevMtpNoAux <== isProofValidNotRevMtpNoAux;
	credentialOwnership.isProofValidNotRevMtpAuxHi <== isProofValidNotRevMtpAuxHi;
	credentialOwnership.isProofValidNotRevMtpAuxHv <== isProofValidNotRevMtpAuxHv;
	credentialOwnership.isProofValidClaimsTreeRoot <== isProofValidClaimsTreeRoot;
	credentialOwnership.isProofValidRevTreeRoot <== isProofValidRevTreeRoot;
	credentialOwnership.isProofValidRootsTreeRoot <== isProofValidRootsTreeRoot;
	for (var i=0; i<issuerLevels; i++) { credentialOwnership.isProofRootMtp[i] <== isProofRootMtp[i]; }
	credentialOwnership.isIdenState <== isIdenState;
}

component main = proveCredentialOwnershipDemo(4, 20);
