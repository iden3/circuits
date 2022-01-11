pragma circom 2.0.0;

include "query.circom";
include "idOwnershipBySignature.circom";
include "credential.circom";

/**
attributeQuery.circom - circuit verifies next iden3 statements:

- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration ?
- query data slots ><= of given value
*/
template AtomicQuery(IdOwnershipLevels, IssuerLevels) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* id ownership signals */
  	signal input id;
    signal input hoIdenState;

	signal input hoClaimsTreeRoot;
	signal input authClaimMtp[IdOwnershipLevels];
	signal input authClaim[8];

	signal input hoRevTreeRoot;
    signal input authClaimNonRevMtp[IdOwnershipLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

	signal input hoRootsTreeRoot;

  	/* signature*/
	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

  	/* claim signals */
  	signal input claimSchema;
    signal input claim[8];
    signal input claimIssuanceMtp[IssuerLevels];
    signal input claimIssuanceClaimsTreeRoot;
    signal input claimIssuanceRevTreeRoot;
    signal input claimIssuanceRootsTreeRoot;
    signal input claimIssuanceIdenState;

    // claim non rev inputs
    signal input claimNonRevMtp[IssuerLevels];
    signal input claimNonRevMtpNoAux;
    signal input claimNonRevMtpAuxHi;
    signal input claimNonRevMtpAuxHv;
    signal input claimNonRevIssuerClaimsTreeRoot;
    signal input claimNonRevIssuerRevTreeRoot;
    signal input claimNonRevIssuerRootsTreeRoot;
    signal input claimNonRevIssuerState;

    /** Query */
    signal input slotIndex;
    signal input value;
    signal input operator;

    /* current time */
    signal input timestamp;

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> End Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* Id ownership check*/
    component userIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);

    userIdOwnership.claimsTreeRoot <== hoClaimsTreeRoot; // currentHolderStateClaimsTreeRoot
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.authClaimMtp[i] <== authClaimMtp[i]; }
    for (var i=0; i<8; i++) { userIdOwnership.authClaim[i] <== authClaim[i]; }

    userIdOwnership.revTreeRoot <== hoRevTreeRoot;  // currentHolderStateClaimsRevTreeRoot
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
    userIdOwnership.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
    userIdOwnership.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
    userIdOwnership.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    userIdOwnership.rootsTreeRoot <== hoRootsTreeRoot; // currentHolderStateClaimsRootsTreeRoot

    userIdOwnership.challenge <== challenge;
    userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    userIdOwnership.challengeSignatureS <== challengeSignatureS;

    userIdOwnership.hoIdenState <== hoIdenState;


    // Check claim is issued to provided identity
    component claimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== claim[i]; }
    claimIdCheck.id <== id;

    // Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== claim[i]; }
    claimSchemaCheck.schema <== claimSchema;

    // verify claim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i=0; i<8; i++) { claimExpirationCheck.claim[i] <== claim[i]; }
    claimExpirationCheck.timestamp <== timestamp;


    // verify claim issued and not revoked
    component vci = verifyClaimIssuanceNonRev(IssuerLevels);
    for (var i=0; i<8; i++) { vci.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) { vci.claimIssuanceMtp[i] <== claimIssuanceMtp[i]; }
    vci.claimIssuanceClaimsTreeRoot <== claimIssuanceClaimsTreeRoot;
    vci.claimIssuanceRevTreeRoot <== claimIssuanceRevTreeRoot;
    vci.claimIssuanceRootsTreeRoot <== claimIssuanceRootsTreeRoot;
    vci.claimIssuanceIdenState <== claimIssuanceIdenState;

    // non revocation status
    for (var i=0; i<IssuerLevels; i++) { vci.claimNonRevMtp[i] <== claimNonRevMtp[i]; }
    vci.claimNonRevMtpNoAux <== claimNonRevMtpNoAux;
    vci.claimNonRevMtpAuxHi <== claimNonRevMtpAuxHi;
    vci.claimNonRevMtpAuxHv <== claimNonRevMtpAuxHv;
    vci.claimNonRevIssuerClaimsTreeRoot <== claimNonRevIssuerClaimsTreeRoot;
    vci.claimNonRevIssuerRevTreeRoot <== claimNonRevIssuerRevTreeRoot;
    vci.claimNonRevIssuerRootsTreeRoot <== claimNonRevIssuerRootsTreeRoot;
    vci.claimNonRevIssuerState <== claimNonRevIssuerState;



    // Query
    component getClaimValue = getValueByIndex();
    for (var i=0; i<8; i++) { getClaimValue.claim[i] <== claim[i]; }
    getClaimValue.index <== slotIndex;

    component query = Query();
		query.in <== getClaimValue.value;
    query.value <== value;
    query.operator <== operator;

    query.out === 1;
}
