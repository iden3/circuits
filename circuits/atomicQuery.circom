pragma circom 2.0.0;

include "simpleQuery.circom";

/**
AtomicQuery - circuit verifies next iden3 statements:
- identity ownership
- claim ownership and issuance state
- claim non revocation state
- claim schema
- claim expiration ?
- query data slots ><= of given value


*/
template AtomicQuery(){
		/* id ownership signals */
  	signal input id;
  	signal input BBJAx;
  	signal input BBJAy;
  	signal input BBJClaimMtp[IdOwnershipLevels];
  	signal input BBJClaimClaimsTreeRoot;
  	signal input BBJClaimRevTreeRoot;
  	signal input BBJClaimRootsTreeRoot;

  	/* signature*/
  	signal input challenge;
  	signal input challengeSignatureR8x;
  	signal input challengeSignatureR8y;
  	signal input challengeSignatureS;

  	/* country claim signals */
		signal input claim[8];
		signal input claimIssuanceMtp[IssuerLevels];
		signal input claimIssuanceClaimsTreeRoot;
		signal input claimIssuanceRevTreeRoot;
		signal input claimIssuanceRootsTreeRoot;
		signal input claimIssuanceIdenState;

		/** Query */
		signal input field;
    signal input value;
    signal input sign;
    signal output queryOut;

		/* Id ownership check*/
		// TODO: switch to IdOwnership template
		component userIdOwnership = IdOwnershipGenesis(IdOwnershipLevels);
		userIdOwnership.id <== id;
		userIdOwnership.userPrivateKey <== userPrivateKey;
		for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.siblings[i] <== BBJClaimMtp[i]; }
		userIdOwnership.claimsTreeRoot <== BBJClaimClaimsTreeRoot;

		/* Country claim checks */
		// check country claim is issued to provided identity
		component claimIdCheck = verifyCredentialSubject();
		for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== claim[i]; }
		claimIdCheck.id <== id;

		// verify claim issueance
		component verifyClaimIssuance = verifyClaimIssuance(IssuerLevels);
        for (var i=0; i<8; i++) { verifyClaimIssuance.claim[i] <== claim[i]; }
        for (var i=0; i<IssuerLevels; i++) { verifyClaimIssuance.claimIssuanceMtp[i] <== countryClaimIssuanceMtp[i]; }
        verifyClaimIssuance.claimIssuanceClaimsTreeRoot <== claimIssuanceClaimsTreeRoot;
        verifyClaimIssuance.claimIssuanceRevTreeRoot <== claimIssuanceRevTreeRoot;
        verifyClaimIssuance.claimIssuanceRootsTreeRoot <== claimIssuanceRootsTreeRoot;
        verifyClaimIssuance.claimIssuanceIdenState <== claimIssuanceIdenState;

		component query = Query();
		query.field <== claim[2];
    query.value <== value;
    query.sign <== sign;

    query.out ==> queryOut;

};

component main = Query();