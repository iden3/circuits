pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../lib/query/comparators.circom";
include "../lib/authV2.circom";
include "../lib/query/query.circom";
include "../lib/utils/idUtils.circom";
include "../lib/utils/spongeHash.circom";


/**
credentialAtomicQuerySigOnChain.circom - query claim value and verify claim issuer signature:

checks:
- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration
- query data slots

idOwnershipLevels - Merkle tree depth level for personal claims
issuerLevels - Merkle tree depth level for claims issued by the issuer
valueArraySize - Number of elements in comparison array for in/notin operation if level = 3 number of values for
comparison ["1", "2", "3"]
idOwnershipLevels - Merkle tree depth level for personal claims
onChainLevels - Merkle tree depth level for Auth claimon chain
*/
template credentialAtomicQuerySigOnChain(issuerLevels, claimLevels, valueArraySize, idOwnershipLevels, onChainLevels) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */
    // flag indicates if merkleized flag set in issuer claim (if set MTP is used to verify that
    // claimPathValue and claimPathKey are stored in the merkle tree) and verification is performed
    // on root stored in the index or value slot
    // if it is not set verification is performed on according to the slotIndex. Value selected from the
    // provided slot. For example if slotIndex is `1` value gets from `i_1` slot. If `4` from `v_1`.
    signal output merklized;

    // userID output signal will be assigned with ProfileID SelectProfile(UserGenesisID, nonce)
    // unless nonce == 0, in which case userID will be assigned with userGenesisID
    signal output userID;
    // circuits query Hash
    signal output circuitQueryHash;

    // we have no constraints for "requestID" in this circuit, it is used as a unique identifier for the request
    // and verifier can use it to identify the request, and verify the proof of specific request in case of multiple query requests
    signal input requestID;

    /* userID ownership signals */
    signal input userGenesisID;
    signal input profileNonce; /* random number */

    // user state
    signal input userState;
    signal input userClaimsTreeRoot;
    signal input userRevTreeRoot;
    signal input userRootsTreeRoot;

    // Auth claim
    signal input authClaim[8];

    // auth claim. merkle tree proof of inclusion to claim tree
    signal input authClaimIncMtp[idOwnershipLevels];

    // auth claim - rev nonce. merkle tree proof of non-inclusion to rev tree
    signal input authClaimNonRevMtp[idOwnershipLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

    // challenge signature
    signal input challenge;
    signal input challengeSignatureR8x;
    signal input challengeSignatureR8y;
    signal input challengeSignatureS;

    // global identity state tree on chain
    signal input gistRoot;
    // proof of inclusion or exclusion of the user in the global state
    signal input gistMtp[onChainLevels];
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;

    /* issuerClaim signals */
    signal input claimSubjectProfileNonce; // nonce of the profile that claim is issued to, 0 if claim is issued to genesisID

    // issuer state
    signal input issuerID;

    // issuer auth proof of existence
    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimMtp[issuerLevels];
    signal input issuerAuthClaimsTreeRoot;
    signal input issuerAuthRevTreeRoot;
    signal input issuerAuthRootsTreeRoot;
    signal output issuerAuthState;

    // issuer auth claim non rev proof
    signal input issuerAuthClaimNonRevMtp[issuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;

    // claim issued by issuer to the user
    signal input issuerClaim[8];
    // issuerClaim non rev inputs
    signal input isRevocationChecked;
    signal input issuerClaimNonRevMtp[issuerLevels];
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
    signal input claimPathMtp[claimLevels];
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
     component auth = AuthV2(idOwnershipLevels, onChainLevels);

    auth.genesisID <== userGenesisID;
    // random number, which should be stored by user
    // if there is a need to generate the same userID (ProfileID) output for different proofs
    auth.profileNonce <== profileNonce;
    // user state
    auth.state <== userState;
    auth.claimsTreeRoot <== userClaimsTreeRoot;
    auth.revTreeRoot <== userRevTreeRoot;
    auth.rootsTreeRoot <== userRootsTreeRoot;

    for (var i= 0; i < 8; i++) { auth.authClaim[i] <== authClaim[i]; }
    for (var i= 0; i < idOwnershipLevels; i++) {
        auth.authClaimIncMtp[i] <== authClaimIncMtp[i]; 
        auth.authClaimNonRevMtp[i] <== authClaimNonRevMtp[i];
    }

    auth.authClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
    auth.authClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;
    auth.authClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;

    // challenge signature
    auth.challenge <== challenge;
    auth.challengeSignatureR8x <== challengeSignatureR8x;
    auth.challengeSignatureR8y <== challengeSignatureR8y;
    auth.challengeSignatureS <== challengeSignatureS;

    // global identity state tree on chain
    auth.gistRoot <== gistRoot;

    // proof of inclusion or exclusion of the user in the global state
    for (var i = 0; i < onChainLevels; i++) { auth.gistMtp[i] <== gistMtp[i]; }
    
    auth.gistMtpAuxHi <== gistMtpAuxHi;
    auth.gistMtpAuxHv <== gistMtpAuxHv;
    auth.gistMtpNoAux <== gistMtpNoAux;

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


    // AuthHash cca3371a6cb1b715004407e325bd993c
    // BigInt: 80551937543569765027552589160822318028
    // https://schema.iden3.io/core/jsonld/auth.jsonld#AuthBJJCredential
    var AUTH_SCHEMA_HASH  = 80551937543569765027552589160822318028;
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
    component smtIssuerAuthClaimExists = checkClaimExists(issuerLevels);
    for (var i=0; i<8; i++) { smtIssuerAuthClaimExists.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<issuerLevels; i++) { smtIssuerAuthClaimExists.claimMTP[i] <== issuerAuthClaimMtp[i]; }
    smtIssuerAuthClaimExists.treeRoot <== issuerAuthClaimsTreeRoot;

    // issuerAuthClaim proof of non-revocation
    //
    component verifyIssuerAuthClaimNotRevoked = checkClaimNotRevoked(issuerLevels);
    verifyIssuerAuthClaimNotRevoked.enabled <== 1;
    for (var i=0; i<8; i++) { verifyIssuerAuthClaimNotRevoked.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<issuerLevels; i++) {
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
    component verifyClaimNotRevoked = checkClaimNotRevoked(issuerLevels);
    verifyClaimNotRevoked.enabled <== isRevocationChecked;
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<issuerLevels; i++) {
        verifyClaimNotRevoked.claimNonRevMTP[i] <== issuerClaimNonRevMtp[i];
    }
    verifyClaimNotRevoked.noAux <== issuerClaimNonRevMtpNoAux;
    verifyClaimNotRevoked.auxHi <== issuerClaimNonRevMtpAuxHi;
    verifyClaimNotRevoked.auxHv <== issuerClaimNonRevMtpAuxHv;
    verifyClaimNotRevoked.treeRoot <== issuerClaimNonRevRevTreeRoot;

    component merklize = getClaimMerklizeRoot();
    for (var i=0; i<8; i++) { merklize.claim[i] <== issuerClaim[i]; }

    // check path/in node exists in merkletree specified by jsonldRoot
    component valueInMT = SMTVerifier(claimLevels);
    valueInMT.enabled <== merklize.flag;  // if merklize flag 0 skip MTP verification
    valueInMT.fnc <== claimPathNotExists; // inclusion
    valueInMT.root <== merklize.out;
    for (var i=0; i<claimLevels; i++) { valueInMT.siblings[i] <== claimPathMtp[i]; }
    valueInMT.oldKey <== claimPathMtpAuxHi;
    valueInMT.oldValue <== claimPathMtpAuxHv;
    valueInMT.isOld0 <== claimPathMtpNoAux;
    valueInMT.key <== claimPathKey;
    valueInMT.value <== claimPathValue;

    // select value from claim by slot index (0-7)
    component getClaimValue = getValueByIndex();
    for (var i=0; i<8; i++) { getClaimValue.claim[i] <== issuerClaim[i]; }
    getClaimValue.index <== slotIndex;

    // select value for query verification,
    // if claim is merklized merklizeFlag = `1|2`, take claimPathValue
    // if not merklized merklizeFlag = `0`, take value from selected slot
    component queryValue = Mux1();
    queryValue.s <== merklize.flag;
    queryValue.c[0] <== getClaimValue.value;
    queryValue.c[1] <== claimPathValue;

    // verify query
    component spongeHash = SpongeHash(valueArraySize);
    component query = Query(valueArraySize);
    query.in <== queryValue.out;
    for (var i=0; i<valueArraySize; i++) { 
        query.value[i] <== value[i];
        spongeHash.in[i] <== value[i];
    }
    query.operator <== operator;

    query.out === 1;

    component queryHasher = Poseidon(4);
    queryHasher.inputs[0] <== claimSchema;
    queryHasher.inputs[1] <== slotIndex;
    queryHasher.inputs[2] <== operator;
    queryHasher.inputs[3] <== spongeHash.out;

    circuitQueryHash <== queryHasher.out;

    /* ProfileID calculation */
    component selectProfile = SelectProfile();
    selectProfile.in <== userGenesisID;
    selectProfile.nonce <== profileNonce;

    userID <== selectProfile.out;
    merklized <== merklize.flag;
}
