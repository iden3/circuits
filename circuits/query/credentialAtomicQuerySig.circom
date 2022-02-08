pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "comparators.circom";
include "../idOwnershipBySignature.circom";
include "query.circom";


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
template CredentialAtomicQuerySig(IdOwnershipLevels, IssuerLevels, valueArraySize) {

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
    // claim signature
    signal input claimSignatureR8x;
    signal input claimSignatureR8y;
    signal input claimSignatureS;

    // issuer state
    signal input issuerID;
    signal input issuerIdenState;
    signal input issuerClaimsTreeRoot;
    signal input issuerRevTreeRoot;
    signal input issuerRootsTreeRoot;

    signal input issuerAuthClaimMtp[IssuerLevels];

    signal input issuerAuthHi;
    signal input issuerAuthHv;
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;

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
    signal input value[valueArraySize];
    signal input operator; // 0 - not in the list, // 1 - in the list

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


    var AUTH_SCHEMA_HASH  = 164867201768971999401702181843803888060;
    // verify claim issued and not revoked
    component hashHi = Poseidon(4);
    hashHi.inputs[0] <== AUTH_SCHEMA_HASH;
    hashHi.inputs[1] <== 0;
    hashHi.inputs[2] <== issuerPubKeyX;
    hashHi.inputs[3] <== issuerPubKeyY;
    hashHi.out === issuerAuthHi;

    // claim proof of existence (isProofExist)
    //
    component smtIssuerAuthClaimExists = SMTVerifier(IssuerLevels);
    smtIssuerAuthClaimExists.enabled <== 1;
    smtIssuerAuthClaimExists.fnc <== 0; // Inclusion
    smtIssuerAuthClaimExists.root <== issuerClaimsTreeRoot;
    for (var i=0; i<IssuerLevels; i++) { smtIssuerAuthClaimExists.siblings[i] <== issuerAuthClaimMtp[i]; }
    smtIssuerAuthClaimExists.oldKey <== 0;
    smtIssuerAuthClaimExists.oldValue <== 0;
    smtIssuerAuthClaimExists.isOld0 <== 0;
    smtIssuerAuthClaimExists.key <== issuerAuthHi;
    smtIssuerAuthClaimExists.value <== issuerAuthHv;

    // claim  check signature
    component verifyClaimSig = verifyClaimSignature();
    for (var i=0; i<8; i++) { verifyClaimSig.claim[i] <== claim[i]; }
    verifyClaimSig.sigR8x <== claimSignatureR8x;
    verifyClaimSig.sigR8y <== claimSignatureR8y;
    verifyClaimSig.sigS <== claimSignatureS;
    verifyClaimSig.pubKeyX <== issuerPubKeyX;
    verifyClaimSig.pubKeyY <== issuerPubKeyY;

    // verify issuer state includes claim
    component verifyClaimIssuanceIdenState = verifyIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.isProofValidClaimsTreeRoot <== claimNonRevIssuerClaimsTreeRoot;
    verifyClaimIssuanceIdenState.isProofValidRevTreeRoot <== claimNonRevIssuerRootsTreeRoot;
    verifyClaimIssuanceIdenState.isProofValidRootsTreeRoot <== claimNonRevIssuerRootsTreeRoot;
    verifyClaimIssuanceIdenState.isIdenState <== claimNonRevIssuerState;

    // non revocation status
    component verifyClaimNotRevoked = verifyCredentialNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) {
        verifyClaimNotRevoked.isProofValidNonRevMtp[i] <== claimNonRevMtp[i];
    }
    verifyClaimNotRevoked.isProofValidNonRevMtpNoAux <== claimNonRevMtpNoAux;
    verifyClaimNotRevoked.isProofValidNonRevMtpAuxHi <== claimNonRevMtpAuxHi;
    verifyClaimNotRevoked.isProofValidNonRevMtpAuxHv <== claimNonRevMtpAuxHv;
    verifyClaimNotRevoked.isProofValidRevTreeRoot <== claimNonRevIssuerRevTreeRoot;

    // query
    component getClaimValue = getValueByIndex();
    for (var i=0; i<8; i++) { getClaimValue.claim[i] <== claim[i]; }
    getClaimValue.index <== slotIndex;

    component q = Query(valueArraySize);
    q.in <== getClaimValue.value;
    q.operator <== operator;
    for(var i = 0; i<valueArraySize; i++){q.value[i] <== value[i];}
    q.out === 1;
}