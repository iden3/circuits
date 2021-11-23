include "idOwnershipBySignature.circom"

template VerifyAuthenticationInformation(IdOwnershipLevels) {

    /* id ownership signals */
	signal input id;
	signal private input BBJAx;
	signal private input BBJAy;
	signal private input BBJClaimMtp[IdOwnershipLevels];
	signal private input BBJClaimClaimsTreeRoot;
	signal private input BBJClaimRevTreeRoot;
	signal private input BBJClaimRootsTreeRoot;
	signal input challenge;
	signal private input challengeSignatureR8x;
	signal private input challengeSignatureR8y;
	signal private input challengeSignatureS;
    signal input state;



    /*
        Id ownership check
    */

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


    // TODO: add non revocation check for identity public key
}
