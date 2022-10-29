pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/query/comparators.circom";
include "../lib/authV2.circom";
include "../lib/query/query.circom";
include "../lib/utils/idUtils.circom";
include "../lib/query/jsonldQuery.circom";


/**
credentialAtomicQuerySig.circom - query claim value and verify claim issuer signature:

checks:
- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration
- query data slots

IdOwnershipLevels - Merkle tree depth level for personal claims
IssuerLevels - Merkle tree depth level for claims issued by the issuer
valueArraySize - Number of elements in comparison array for in/notin operation if level = 3 number of values for
comparison ["1", "2", "3"]

*/
template credentialAtomicQuerySigV2(IssuerLevels, ClaimLevels, valueArraySize) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /* 0n-chain SMT state proof */
//    signal input globalSmtRoot;
//    signal input globalSmtMtp[OnChainSmtLevels];
//    signal input globalSmtMtpAuxHi;
//    signal input globalSmtMtpAuxHv;
//    signal input globalSmtMtpNoAux;

    // userID output signal will be assigned with ProfileID ProfileID(UserID, nonce),
    // unless nonce == 0, in which case userID will be assigned with userGenesisID
    signal output userID;

    /* userID ownership signals */
    signal input userGenesisID;
//    signal input userState;
    signal input nonce; /* random number */

//    signal input userClaimsTreeRoot;
//    signal input userAuthClaimMtp[IdOwnershipLevels];
//    signal input userAuthClaim[8];

//    signal input userRevTreeRoot;
//    signal input userAuthClaimNonRevMtp[IdOwnershipLevels];
//    signal input userAuthClaimNonRevMtpNoAux;
//    signal input userAuthClaimNonRevMtpAuxHi;
//    signal input userAuthClaimNonRevMtpAuxHv;

//    signal input userRootsTreeRoot;

    /* signature*/
//    signal input challenge;
//    signal input challengeSignatureR8x;
//    signal input challengeSignatureR8y;
//    signal input challengeSignatureS;

    /* issuerClaim signals */
    signal input claimSubjectProfileNonce; // nonce of the profile that claim is issued to, 0 if claim is issued to genesisID


    // issuer state
    signal input issuerID;

    // issuer auth proof of existence
    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimMtp[IssuerLevels];
    signal input issuerAuthClaimsTreeRoot;
    signal input issuerAuthRevTreeRoot;
    signal input issuerAuthRootsTreeRoot;
    signal output issuerAuthState;

    // issuer auth claim non rev proof
    signal input issuerAuthClaimNonRevMtp[IssuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;

    // claim issued by issuer to the user
    signal input issuerClaim[8];
    // issuerClaim non rev inputs
    signal input issuerClaimNonRevMtp[IssuerLevels];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;
    signal input issuerClaimNonRevClaimsTreeRoot;
    signal input issuerClaimNonRevRevTreeRoot;
    signal input issuerClaimNonRevRootsTreeRoot;
    signal input issuerClaimNonRevState;

    // issuerClaim signature
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;

    /* current time */
    signal input timestamp;

    /** Query */
    signal input claimSchema;

    signal input claimPathNotExists; // 0 for inclusion, 1 for non-inclusion
    signal input claimPathMtp[ClaimLevels];
    signal input claimPathMtpNoAux; // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
    signal input claimPathMtpAuxHi; // 0 for inclusion proof
    signal input claimPathMtpAuxHv; // 0 for inclusion proof
    signal input claimPathKey; // hash of path in merklized json-ld document
    signal input claimPathValue; // value in this path in merklized json-ld document

    signal input slotIndex;
    signal input operator;
    signal input value[valueArraySize];


    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> End Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    // Check issuerClaim is issued to provided identity
    component claimIdCheck = verifyCredentialSubjectProfile();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== issuerClaim[i]; }
    claimIdCheck.id <== userGenesisID;
    claimIdCheck.nonce <== claimSubjectProfileNonce;

    // Verify issuerClaim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== claimSchema;

    // verify issuerClaim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i=0; i<8; i++) { claimExpirationCheck.claim[i] <== issuerClaim[i]; }
    claimExpirationCheck.timestamp <== timestamp;


    var AUTH_SCHEMA_HASH  = 304427537360709784173770334266246861770;
    component issuerSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { issuerSchemaCheck.claim[i] <== issuerAuthClaim[i]; }
    issuerSchemaCheck.schema <== AUTH_SCHEMA_HASH;
    // verify authClaim issued and not revoked
    // calculate issuerAuthState
    component issuerAuthStateComponent = getIdenState();
    issuerAuthStateComponent.claimsTreeRoot <== issuerAuthClaimsTreeRoot;
    issuerAuthStateComponent.revTreeRoot <== issuerAuthRevTreeRoot;
    issuerAuthStateComponent.rootsTreeRoot <== issuerAuthRootsTreeRoot;

    issuerAuthState <== issuerAuthStateComponent.idenState;


    // issuerAuthClaim proof of existence (isProofExist)
    //
    component smtIssuerAuthClaimExists = checkClaimExists(IssuerLevels);
    for (var i=0; i<8; i++) { smtIssuerAuthClaimExists.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { smtIssuerAuthClaimExists.claimMTP[i] <== issuerAuthClaimMtp[i]; }
    smtIssuerAuthClaimExists.treeRoot <== issuerAuthClaimsTreeRoot;

    // issuerAuthClaim proof of non-revocation
    //
    component verifyIssuerAuthClaimNotRevoked = checkClaimNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyIssuerAuthClaimNotRevoked.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) {
        verifyIssuerAuthClaimNotRevoked.claimNonRevMTP[i] <== issuerAuthClaimNonRevMtp[i];
    }
    verifyIssuerAuthClaimNotRevoked.noAux <== issuerAuthClaimNonRevMtpNoAux;
    verifyIssuerAuthClaimNotRevoked.auxHi <== issuerAuthClaimNonRevMtpAuxHi;
    verifyIssuerAuthClaimNotRevoked.auxHv <== issuerAuthClaimNonRevMtpAuxHv;
    verifyIssuerAuthClaimNotRevoked.treeRoot <== issuerClaimNonRevRevTreeRoot;

    component issuerAuthPubKey = getPubKeyFromClaim();
    for (var i=0; i<8; i++){ issuerAuthPubKey.claim[i] <== issuerAuthClaim[i]; }

    // issuerClaim  check signature
    component verifyClaimSig = verifyClaimSignature();
    for (var i=0; i<8; i++) { verifyClaimSig.claim[i] <== issuerClaim[i]; }
    verifyClaimSig.sigR8x <== issuerClaimSignatureR8x;
    verifyClaimSig.sigR8y <== issuerClaimSignatureR8y;
    verifyClaimSig.sigS <== issuerClaimSignatureS;
    verifyClaimSig.pubKeyX <== issuerAuthPubKey.Ax;
    verifyClaimSig.pubKeyY <== issuerAuthPubKey.Ay;

    // verify issuer state includes issuerClaim
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.claimsTreeRoot <== issuerClaimNonRevClaimsTreeRoot;
    verifyClaimIssuanceIdenState.revTreeRoot <== issuerClaimNonRevRevTreeRoot;
    verifyClaimIssuanceIdenState.rootsTreeRoot <== issuerClaimNonRevRootsTreeRoot;
    verifyClaimIssuanceIdenState.expectedState <== issuerClaimNonRevState;

    // non revocation status
    component verifyClaimNotRevoked = checkClaimNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) {
        verifyClaimNotRevoked.claimNonRevMTP[i] <== issuerClaimNonRevMtp[i];
    }
    verifyClaimNotRevoked.noAux <== issuerClaimNonRevMtpNoAux;
    verifyClaimNotRevoked.auxHi <== issuerClaimNonRevMtpAuxHi;
    verifyClaimNotRevoked.auxHv <== issuerClaimNonRevMtpAuxHv;
    verifyClaimNotRevoked.treeRoot <== issuerClaimNonRevRevTreeRoot;

    // query
    // TODO: add support for old queries
//    component getClaimValue = getValueByIndex();
//    for (var i=0; i<8; i++) { getClaimValue.claim[i] <== issuerClaim[i]; }
//    getClaimValue.index <== slotIndex;
//
//    component q = Query(valueArraySize);
//    q.in <== getClaimValue.value;
//    q.operator <== operator;
//    for(var i = 0; i<valueArraySize; i++){q.value[i] <== value[i];}
//    q.out === 1;

    // Query
    component getClaimValue = getValueByIndex();
    for (var i=0; i<8; i++) { getClaimValue.claim[i] <== issuerClaim[i]; }
    getClaimValue.index <== 2; // we expect to find json-ld claim tree root in 3rd slot of index

    component q = JsonLDQuery(valueArraySize, ClaimLevels);

    q.jsonldRoot <== getClaimValue.value;
    q.notExists <== claimPathNotExists;
    for(var i = 0; i<ClaimLevels; i++){q.mtp[i] <== claimPathMtp[i];}
    q.auxNodeKey <== claimPathMtpAuxHi;
    q.auxNodeValue <== claimPathMtpAuxHv;
    q.auxNodeEmpty <== claimPathMtpNoAux;
    q.path <== claimPathKey;
    q.in <== claimPathValue;
    q.operator <== operator;
    for(var i = 0; i<valueArraySize; i++){q.value[i] <== value[i];}

    q.out === 1;


    // TODO calculate USERID
    /* ProfileID calculation */
    component calcProfile = ProfileID();
    calcProfile.in <== userGenesisID;
    calcProfile.nonce <== nonce;

    component isSaltZero = IsZero();
    isSaltZero.in <== nonce;

    component selectProfile = Mux1();
    selectProfile.s <== isSaltZero.out;
    selectProfile.c[0] <== calcProfile.out;
    selectProfile.c[1] <== userGenesisID;

    userID <== selectProfile.out;
}
