pragma circom 2.0.0;

include "simpleQuery.circom";
include "idOwnershipBySignature.circom";
include "credential.circom";

/**
attributeQuery.circom - circuit verifies next iden3 statements:

- identity ownership
- claim ownership and issuance state
- claim non revocation state
- claim schema
- claim expiration ?
- query data slots ><= of given value


*/

template attrQuery(IdOwnershipLevels) {
		log(1);

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

  	/* claim signals */
		signal input claim[8];
		signal input claimIssuanceMtp[IdOwnershipLevels];
		signal input claimIssuanceClaimsTreeRoot;
		signal input claimIssuanceRevTreeRoot;
		signal input claimIssuanceRootsTreeRoot;
		signal input claimIssuanceIdenState;

		/** Query */
//		signal input field;
//    signal input value;
//    signal input sign;
//    signal output queryOut;

		log(2);
		/* Id ownership check*/
		component userIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);
		userIdOwnership.id <== id;
		userIdOwnership.userPublicKeyAx <== BBJAx;
		userIdOwnership.userPublicKeyAy <== BBJAy;
		for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.siblings[i] <== BBJClaimMtp[i]; }
		userIdOwnership.claimsTreeRoot <== BBJClaimClaimsTreeRoot;
		userIdOwnership.revTreeRoot <== BBJClaimRevTreeRoot;
		userIdOwnership.rootsTreeRoot <== BBJClaimRootsTreeRoot;
		userIdOwnership.challenge <== challenge;
		userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
		userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
		userIdOwnership.challengeSignatureS <== challengeSignatureS;

		log(3);
		// Check claim is issued to provided identity
		component claimIdCheck = verifyCredentialSubject();
		for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== claim[i]; }
		claimIdCheck.id <== id;

		log(4);
		// verify claim issueance
		component verifyClaimIssuance = verifyClaimIssuance(IdOwnershipLevels);
		for (var i=0; i<8; i++) { verifyClaimIssuance.claim[i] <== claim[i]; }
		for (var i=0; i<IdOwnershipLevels; i++) { verifyClaimIssuance.claimIssuanceMtp[i] <== claimIssuanceMtp[i]; }
		verifyClaimIssuance.claimIssuanceClaimsTreeRoot <== claimIssuanceClaimsTreeRoot;
		verifyClaimIssuance.claimIssuanceRevTreeRoot <== claimIssuanceRevTreeRoot;
		verifyClaimIssuance.claimIssuanceRootsTreeRoot <== claimIssuanceRootsTreeRoot;
		verifyClaimIssuance.claimIssuanceIdenState <== claimIssuanceIdenState;

		// verify claim revocation status

		//##### Verify query
//		component query = Query();
//		query.field <== claim[2];
//    query.value <== value;
//    query.sign <== sign;
//
//    query.out ==> queryOut;

}

component main{public [challenge, id]} = attrQuery(4);