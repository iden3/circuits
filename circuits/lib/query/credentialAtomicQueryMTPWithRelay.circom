pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "comparators.circom";
include "../idOwnershipBySignatureWithRelay.circom";
include "query.circom";


/**
credentialAtomicQueryMTP.circom - query claim value and verify claim MTP

checks:
- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration ?
- query data slots

IdOwnershipLevels - Merkle tree depth level for personal claims
IssuerLevels - Merkle tree depth level for claims issued by the issuer
valueLevels - Number of elements in comparison array for in/notin operation if level =3 number of values for
comparison ["1", "2", "3"]

*/
template CredentialAtomicQueryMTPWithRelay(IdOwnershipLevels, IssuerLevels, RelayLevels, valueArraySize) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* user id ownership signals */
    signal input userID;

    signal input relayState;
    signal input userStateInRelayClaimMtp[RelayLevels];
    signal input userStateInRelayClaim[8];
	signal input relayProofValidClaimsTreeRoot;
	signal input relayProofValidRevTreeRoot;
	signal input relayProofValidRootsTreeRoot;    

    signal input userClaimsTreeRoot;
    signal input authClaimMtp[IdOwnershipLevels];
    signal input authClaim[8];

    signal input userRevTreeRoot;
    signal input authClaimNonRevMtp[IdOwnershipLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

    signal input userRootsTreeRoot;

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
    signal input issuerID;

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
    signal input value[valueArraySize];
    signal input operator;

    /* current time */
    signal input timestamp;

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> End Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* Id ownership check*/
    component userIdOwnership = IdOwnershipBySignatureWithRelay(IdOwnershipLevels, RelayLevels);

    userIdOwnership.claimsTreeRoot <== userClaimsTreeRoot; // currentUserStateClaimsTreeRoot
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.authClaimMtp[i] <== authClaimMtp[i]; }
    for (var i=0; i<8; i++) { userIdOwnership.authClaim[i] <== authClaim[i]; }

    userIdOwnership.revTreeRoot <== userRevTreeRoot;  // currentUserStateClaimsRevTreeRoot
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
    userIdOwnership.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
    userIdOwnership.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
    userIdOwnership.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    userIdOwnership.rootsTreeRoot <== userRootsTreeRoot; // currentUserStateClaimsRootsTreeRoot

    userIdOwnership.challenge <== challenge;
    userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    userIdOwnership.challengeSignatureS <== challengeSignatureS;

    userIdOwnership.userID <== userID;

    userIdOwnership.relayState <== relayState;
    for (var i=0; i<RelayLevels; i++) { userIdOwnership.userStateInRelayClaimMtp[i] <== userStateInRelayClaimMtp[i]; }
    for (var i=0; i<8; i++) { userIdOwnership.userStateInRelayClaim[i] <== userStateInRelayClaim[i]; }
	userIdOwnership.relayProofValidClaimsTreeRoot <== relayProofValidClaimsTreeRoot;
	userIdOwnership.relayProofValidRevTreeRoot <== relayProofValidRevTreeRoot;
	userIdOwnership.relayProofValidRootsTreeRoot <== relayProofValidRootsTreeRoot;

    // Check claim is issued to provided identity
    component claimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== claim[i]; }
    claimIdCheck.id <== userID;

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

    component q = Query(valueArraySize);
    q.in <== getClaimValue.value;
    q.operator <== operator;
    for(var i = 0; i<valueArraySize; i++){q.value[i] <== value[i];}

    q.out === 1;

}
