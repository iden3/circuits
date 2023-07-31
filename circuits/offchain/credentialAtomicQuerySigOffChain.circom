pragma circom 2.1.1;
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/query/comparators.circom";
include "../auth/authV2.circom";
include "../lib/query/query.circom";
include "../lib/utils/idUtils.circom";


/**
credentialAtomicQuerySig.circom - query claim value and verify claim issuer signature:

checks:
- identity ownership
- verify credential subject (verify that identity is an owner of a claim )
- claim schema
- claim ownership and issuance state
- claim non revocation state
- claim expiration
- query JSON-LD claim's field

idOwnershipLevels - Merkle tree depth level for personal claims
issuerLevels - Merkle tree depth level for claims issued by the issuer
claimLevels - Merkle tree depth level for claim JSON-LD document
valueArraySize - Number of elements in comparison array for in/notin operation if level = 3 number of values for
comparison ["1", "2", "3"]

*/
template credentialAtomicQuerySigOffChain(issuerLevels, claimLevels, valueArraySize) {

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */
    // we have no constraints for "requestID" in this circuit, it is used as a unique identifier for the request
    // and verifier can use it to identify the request, and verify the proof of specific request in case of multiple query requests
    signal input requestID;
    
    // flag indicates if merklized flag set in issuer claim (if set MTP is used to verify that
    // claimPathValue and claimPathKey are stored in the merkle tree) and verification is performed
    // on root stored in the index or value slot
    // if it is not set verification is performed on according to the slotIndex. Value selected from the
    // provided slot. For example if slotIndex is `1` value gets from `i_1` slot. If `4` from `v_1`.
    signal output merklized;

    // userID output signal will be assigned with ProfileID SelectProfile(UserGenesisID, nonce)
    // unless nonce == 0, in which case userID will be assigned with userGenesisID
    signal output userID;

    /* userID ownership signals */
    signal input userGenesisID;
    signal input profileNonce; /* random number */

    /* issuerClaim signals */
    signal input claimSubjectProfileNonce; // nonce of the profile that claim is issued to, 0 if claim is issued to genesisID

    // issuer ID
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

    /////////////////////////////////////////////////////////////////

    // Check issuerClaim is issued to provided identity
    verifyCredentialSubjectProfile()(
        issuerClaim,
        userGenesisID,
        claimSubjectProfileNonce
    );

    // Verify issuerClaim schema
    verifyCredentialSchema()(1, issuerClaim, claimSchema);

    // verify issuerClaim expiration time
    verifyExpirationTime()(issuerClaim, timestamp);

    /////////////////////////////////////////////////////////////////

    // verify issuerAuthClaim Schema
    // AuthHash cca3371a6cb1b715004407e325bd993c
    // BigInt: 80551937543569765027552589160822318028
    // https://schema.iden3.io/core/jsonld/auth.jsonld#AuthBJJCredential
    verifyCredentialSchema()(
        1,
        issuerAuthClaim,
        80551937543569765027552589160822318028
    );

    // verify authClaim issued and not revoked
    // calculate issuerAuthState
    issuerAuthState <== getIdenState()(
        issuerAuthClaimsTreeRoot,
        issuerAuthRevTreeRoot,
        issuerAuthRootsTreeRoot
    );

    // issuerAuthClaim proof of existence (isProofExist)
    checkClaimExists(issuerLevels)(
        issuerAuthClaim,
        issuerAuthClaimMtp,
        issuerAuthClaimsTreeRoot
    );

    // issuerAuthClaim proof of non-revocation
    checkClaimNotRevoked(issuerLevels)(
        enabled <== 1,
        claim <== issuerAuthClaim,
        claimNonRevMTP <== issuerAuthClaimNonRevMtp,
        noAux <== issuerAuthClaimNonRevMtpNoAux,
        auxHi <== issuerAuthClaimNonRevMtpAuxHi,
        auxHv <== issuerAuthClaimNonRevMtpAuxHv,
        treeRoot <== issuerClaimNonRevRevTreeRoot
    );

    component issuerAuthPubKey = getPubKeyFromClaim();
    issuerAuthPubKey.claim <== issuerAuthClaim;

    // issuerClaim  check signature
    verifyClaimSignature()(
        issuerClaim,
        issuerClaimSignatureR8x,
        issuerClaimSignatureR8y,
        issuerClaimSignatureS,
        issuerAuthPubKey.Ax,
        issuerAuthPubKey.Ay
    );

    /////////////////////////////////////////////////////////////////

    // non revocation status
    checkClaimNotRevoked(issuerLevels)(
        enabled <== isRevocationChecked,
        claim <== issuerClaim,
        claimNonRevMTP <== issuerClaimNonRevMtp,
        noAux <== issuerClaimNonRevMtpNoAux,
        auxHi <== issuerClaimNonRevMtpAuxHi,
        auxHv <== issuerClaimNonRevMtpAuxHv,
        treeRoot <== issuerClaimNonRevRevTreeRoot
    );

    // verify issuer state for claim non-revocation proof
    checkIdenStateMatchesRoots()(
        issuerClaimNonRevClaimsTreeRoot,
        issuerClaimNonRevRevTreeRoot,
        issuerClaimNonRevRootsTreeRoot,
        issuerClaimNonRevState
    );

    /////////////////////////////////////////////////////////////////

    component merklize = getClaimMerklizeRoot();
    merklize.claim <== issuerClaim;

    merklized <== merklize.flag;

    // check path/in node exists in merkletree specified by jsonldRoot
    SMTVerifier(claimLevels)(
        enabled <== merklize.flag,  // if merklize flag 0 skip MTP verification
        fnc <== claimPathNotExists, // inclusion
        root <== merklize.out,
        siblings <== claimPathMtp,
        oldKey <== claimPathMtpAuxHi,
        oldValue <== claimPathMtpAuxHv,
        isOld0 <== claimPathMtpNoAux,
        key <== claimPathKey,
        value <== claimPathValue
    );

    // select value from claim by slot index (0-7)
    signal slotValue <== getValueByIndex()(issuerClaim, slotIndex);

    // select value for query verification,
    // if claim is merklized merklizeFlag = `1|2`, take claimPathValue
    // if not merklized merklizeFlag = `0`, take value from selected slot
    signal fieldValue <== Mux1()(
        [slotValue, claimPathValue],
        merklize.flag
    );

    /////////////////////////////////////////////////////////////////

    // verify query
    signal querySatisfied <== Query(valueArraySize)(
        in <== fieldValue,
        value <== value,
        operator <== operator
    );

    querySatisfied === 1;

    /* ProfileID calculation */
    userID <== SelectProfile()(userGenesisID, profileNonce);
}
