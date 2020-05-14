include "../credential.circom"

// buildClaimOtherIdenDemo builds a ClaimOtherIden (an example claim which has
// Subject = OtherIden, SubjectPos = Index).  The IndexSlot bytes in i0 and the
// ValueSlot bytes in v0 are set to 0 (unused) for simplicity.
template buildClaimOtherIdenDemo() {
	signal input claimI2_3[2]; // from [62]byte
	signal input claimV1_3[3]; // from [93]byte
	signal input revNonce;
	signal input id;

	signal output claim[8];

	// ClaimOtherIden with Index bytes in i0 at 0 (indexBytes[:19] == zero)
	claim[0] <== 37037603335494959104;
	claim[1] <== id;
	for (var i=0; i<2; i++) {
		claim[2 + i] <== claimI2_3[i];
	}

	// ClaimOtherIden with Value bytes in v0 at 0 (valueBytes[:27] == zero)
	claim[4] <== revNonce;
	for (var i=0; i<3; i++) {
		claim[5 + i] <== claimV1_3[i];
	}
}

// proveCredentialOwnershipDemo proves credential ownership of a ClaimOtherIden
// (simplified Demo version) only revealing the issuer identity state and the
// IndexSlot and ValueSlot data.
template proveCredentialOwnershipDemo(IdOwnershipLevels, IssuerLevels) {
	var idOwnershipLevels = IdOwnershipLevels + 1;
	var issuerLevels = IssuerLevels + 1;

	// F. issuer recent idenState
	signal input isIdenState; // make this public input the first one for convenience

	// A
	// signal input claim[8];
	signal input claimI2_3[2];
	signal input claimV1_3[3];
	signal private input revNonce;
	signal private input id;

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

	component claimDemo = buildClaimOtherIdenDemo();
	for (var i=0; i<2; i++) { claimDemo.claimI2_3[i] <== claimI2_3[i]; }
	for (var i=0; i<3; i++) { claimDemo.claimV1_3[i] <== claimV1_3[i]; }
	claimDemo.revNonce <== revNonce;
	claimDemo.id <== id;

	component credentialOwnership = proveCredentialOwnership(IdOwnershipLevels, IssuerLevels);
	for (var i=0; i<8; i++) { credentialOwnership.claim[i] <== claimDemo.claim[i]; }
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

component main = proveCredentialOwnershipDemo(4, 16);
