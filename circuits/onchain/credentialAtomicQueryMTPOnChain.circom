pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../lib/query/comparators.circom";
include "../lib/authV2.circom";
include "../lib/query/query.circom";
include "../lib/utils/idUtils.circom";
include "../lib/query/jsonldQuery.circom";
include "../lib/utils/valueHasher.circom";

/**
credentialJsonLDAtomicQueryMTP.circom - query issuerClaim value and verify issuerClaim MTP

checks:
- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration ?
- query JSON-LD claaim's field

issuerLevels - Merkle tree depth level for claims issued by the issuer
claimLevels - Merkle tree depth level for claim JSON-LD document
valueLevels - Number of elements in comparison array for in/notin operation if level =3 number of values for
idOwnershipLevels - Merkle tree depth level for personal claims
onChainLevels - Merkle tree depth level for Auth claimon chain
comparison ["1", "2", "3"]

*/
template CredentialAtomicQueryMTPOnChain(issuerLevels, claimLevels, valueArraySize, idOwnershipLevels, onChainLevels) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    // flag indicates if merkleized flag set in issuer claim (if set MTP is used to verify that
    // claimPathValue and claimPathKey are stored in the merkle tree) and verification is performed
    // on root stored in the index or value slot
    // if it is not set verification is performed on according to the slotIndex. Value selected from the
    // provided slot. For example if slotIndex is `1` value gets from `i_1` slot. If `4` from `v_1`.
    signal output merklized;

    // userID output signal will be assigned with ProfileID ProfileID(UserID, nonce),
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


    signal input issuerID;

    /* issuerClaim signals */
    signal input issuerClaim[8];
    signal input issuerClaimMtp[ issuerLevels];
    signal input issuerClaimClaimsTreeRoot;
    signal input issuerClaimRevTreeRoot;
    signal input issuerClaimRootsTreeRoot;
    signal input issuerClaimIdenState;

    // issuerClaim non rev inputs
    signal input isRevocationChecked;
    signal input issuerClaimNonRevMtp[ issuerLevels];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;
    signal input issuerClaimNonRevClaimsTreeRoot;
    signal input issuerClaimNonRevRevTreeRoot;
    signal input issuerClaimNonRevRootsTreeRoot;
    signal input issuerClaimNonRevState;

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

    // check user ownership

    // verify issuerClaim issued and not revoked
    component vci = verifyClaimIssuanceNonRev(issuerLevels);
    for (var i = 0; i < 8; i++) { vci.claim[i] <== issuerClaim[i]; }
    for (var i = 0; i < issuerLevels; i++) { vci.claimIssuanceMtp[i] <== issuerClaimMtp[i]; }
    vci.claimIssuanceClaimsTreeRoot <== issuerClaimClaimsTreeRoot;
    vci.claimIssuanceRevTreeRoot <== issuerClaimRevTreeRoot;
    vci.claimIssuanceRootsTreeRoot <== issuerClaimRootsTreeRoot;
    vci.claimIssuanceIdenState <== issuerClaimIdenState;

    // non revocation status
    vci.enabledNonRevCheck <== isRevocationChecked;
    for (var i = 0; i < issuerLevels; i++) { vci.claimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    vci.claimNonRevMtpNoAux <== issuerClaimNonRevMtpNoAux;
    vci.claimNonRevMtpAuxHi <== issuerClaimNonRevMtpAuxHi;
    vci.claimNonRevMtpAuxHv <== issuerClaimNonRevMtpAuxHv;
    vci.claimNonRevIssuerClaimsTreeRoot <== issuerClaimNonRevClaimsTreeRoot;
    vci.claimNonRevIssuerRevTreeRoot <== issuerClaimNonRevRevTreeRoot;
    vci.claimNonRevIssuerRootsTreeRoot <== issuerClaimNonRevRootsTreeRoot;
    vci.claimNonRevIssuerState <== issuerClaimNonRevState;

    // Check issuerClaim is issued to provided identity
    component claimIdCheck = verifyCredentialSubjectProfile();
    for (var i = 0; i < 8; i++) { claimIdCheck.claim[i] <== issuerClaim[i]; }
    claimIdCheck.id <== userGenesisID;
    claimIdCheck.nonce <== claimSubjectProfileNonce;

    // Verify issuerClaim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i = 0; i < 8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== claimSchema;

    // verify issuerClaim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i = 0; i < 8; i++) { claimExpirationCheck.claim[i] <== issuerClaim[i]; }
    claimExpirationCheck.timestamp <== timestamp;

    component merklize = getClaimMerklizeRoot();
    for (var i = 0; i < 8; i++) { merklize.claim[i] <== issuerClaim[i]; }
    merklized <== merklize.flag;

    // check path/in node exists in merkletree specified by jsonldRoot
    component valueInMT = SMTVerifier(claimLevels);
    valueInMT.enabled <== merklize.flag;  // if merklize flag 0 skip MTP verification
    valueInMT.fnc <== claimPathNotExists; // inclusion
    valueInMT.root <== merklize.out;
    for (var i = 0; i < claimLevels; i++) { valueInMT.siblings[i] <== claimPathMtp[i]; }
    valueInMT.oldKey <== claimPathMtpAuxHi;
    valueInMT.oldValue <== claimPathMtpAuxHv;
    valueInMT.isOld0 <== claimPathMtpNoAux;
    valueInMT.key <== claimPathKey;
    valueInMT.value <== claimPathValue;

    // select value from claim by slot index (0-7)
    component getClaimValue = getValueByIndex();
    for (var i = 0; i < 8; i++) { getClaimValue.claim[i] <== issuerClaim[i]; }
    getClaimValue.index <== slotIndex;

    // select value for query verification,
    // if claim is merklized merklizeFlag = `1|2`, take claimPathValue
    // if not merklized merklizeFlag = `0`, take value from selected slot
    component queryValue = Mux1();
    queryValue.s <== merklize.flag;
    queryValue.c[0] <== getClaimValue.value;
    queryValue.c[1] <== claimPathValue;

    // verify query
    component query = Query(valueArraySize);
    query.in <== queryValue.out;
    query.operator <== operator;
    component valueHasher = ValueHasher(valueArraySize);
    for (var i = 0; i < valueArraySize; i++) { 
        query.value[i] <== value[i];
        valueHasher.in[i] <== value[i];
    }

    component queryHasher = Poseidon(4);
    queryHasher.inputs[0] <== claimSchema;
    queryHasher.inputs[1] <== slotIndex;
    queryHasher.inputs[2] <== operator;
    queryHasher.inputs[3] <== valueHasher.out;

    circuitQueryHash <== queryHasher.out;

    query.out === 1;

    userID <== auth.userID;
}
