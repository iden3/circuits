pragma circom 2.1.1;
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../lib/query/comparators.circom";
include "../auth/authV2.circom";
include "../lib/query/query.circom";
include "../lib/utils/idUtils.circom";
include "../lib/utils/spongeHash.circom";

/**
credentialAtomicQueryV3OnChain.circom - query claim value and verify claim issuer signature or mtp:

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
idOwnershipLevels - Merkle tree depth level for personal claims
onChainLevels - Merkle tree depth level for Auth claim on-chain
*/
template credentialAtomicQueryV3OnChain(issuerLevels, claimLevels, valueArraySize, idOwnershipLevels, onChainLevels) {
    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */
    // flag indicates if merklized flag set in issuer claim (if set MTP is used to verify that
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

    
    signal input proofType;  // sig 0, mtp 1

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

    // issuer ID
    signal input issuerID;

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


    // MTP specific
    signal input issuerClaimMtp[issuerLevels];
    signal input issuerClaimClaimsTreeRoot;
    signal input issuerClaimRevTreeRoot;
    signal input issuerClaimRootsTreeRoot;
    signal input issuerClaimIdenState;

    // Sig specific
    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimMtp[issuerLevels];
    signal input issuerAuthClaimsTreeRoot;
    signal input issuerAuthRevTreeRoot;
    signal input issuerAuthRootsTreeRoot;
    signal input issuerAuthClaimNonRevMtp[issuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;


    // Sig specific output
    signal output issuerAuthState;

    /*
    >>>>>>>>>>>>>>>>>>>>>>>>>>> End Inputs <<<<<<<<<<<<<<<<<<<<<<<<<<<<
    */

    /////////////////////////////////////////////////////////////////

    checkAuthV2(idOwnershipLevels, onChainLevels)(
        1, // enabled
        userGenesisID,
        profileNonce,
        userState, // user state
        userClaimsTreeRoot,
        userRevTreeRoot,
        userRootsTreeRoot,
        authClaim,
        authClaimIncMtp,
        authClaimNonRevMtp,
        authClaimNonRevMtpNoAux,
        authClaimNonRevMtpAuxHi,
        authClaimNonRevMtpAuxHv,
        challenge, // challenge & signature
        challengeSignatureR8x,
        challengeSignatureR8y,
        challengeSignatureS,
        gistRoot, // global identity state tree on chain
        gistMtp, // proof of inclusion or exclusion of the user in the global state
        gistMtpAuxHi,
        gistMtpAuxHv,
        gistMtpNoAux
    );

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

    signal isSig;
    signal isMTP;
    isSig  <== 1 - proofType;
    isMTP <== proofType;
    isSig * isMTP === 0;

    issuerAuthState <== sigFlow(issuerLevels)(
        enabled <== isSig,
        issuerAuthClaim <== issuerAuthClaim,
        issuerAuthClaimsTreeRoot <== issuerAuthClaimsTreeRoot,
        issuerAuthRevTreeRoot <== issuerAuthRevTreeRoot,
        issuerAuthRootsTreeRoot <== issuerAuthRootsTreeRoot,
        issuerAuthClaimMtp <== issuerAuthClaimMtp,
        issuerAuthClaimNonRevMtp <== issuerAuthClaimNonRevMtp,
        issuerAuthClaimNonRevMtpNoAux <== issuerAuthClaimNonRevMtpNoAux,
        issuerAuthClaimNonRevMtpAuxHi <== issuerAuthClaimNonRevMtpAuxHi,
        issuerAuthClaimNonRevMtpAuxHv <== issuerAuthClaimNonRevMtpAuxHv,
        issuerClaimNonRevRevTreeRoot <== issuerClaimNonRevRevTreeRoot,
        issuerClaim <== issuerClaim,
        issuerClaimSignatureR8x <== issuerClaimSignatureR8x,
        issuerClaimSignatureR8y <== issuerClaimSignatureR8y,
        issuerClaimSignatureS <== issuerClaimSignatureS
    );

    mtpFlow(issuerLevels)(
        enabled <== isMTP,
        issuerClaim <== issuerClaim,
        issuerClaimMtp <== issuerClaimMtp,
        issuerClaimClaimsTreeRoot <== issuerClaimClaimsTreeRoot,
        issuerClaimRevTreeRoot <== issuerClaimRevTreeRoot,
        issuerClaimRootsTreeRoot <== issuerClaimRootsTreeRoot,
        issuerClaimIdenState <== issuerClaimIdenState
    );

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
        1,
        issuerClaimNonRevClaimsTreeRoot,
        issuerClaimNonRevRevTreeRoot,
        issuerClaimNonRevRootsTreeRoot,
        issuerClaimNonRevState
    );

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

    // verify query hash matches
    signal valueHash <== SpongeHash(valueArraySize, 6)(value); // 6 - max size of poseidon hash available on-chain

    circuitQueryHash <== Poseidon(6)([
        claimSchema,
        slotIndex,
        operator,
        claimPathKey,
        claimPathNotExists, // TODO: check if this value should be here
        valueHash
    ]);

    /* ProfileID calculation */
    userID <== SelectProfile()(userGenesisID, profileNonce);
}


template sigFlow(issuerLevels) {
    signal input enabled;
    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimsTreeRoot;
    signal input issuerAuthRevTreeRoot;
    signal input issuerAuthRootsTreeRoot;
    signal input issuerAuthClaimMtp[issuerLevels];
    signal input issuerAuthClaimNonRevMtp[issuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;
    signal input issuerClaimNonRevRevTreeRoot;
    signal input issuerClaim[8];
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;
    signal output issuerAuthState;

    verifyCredentialSchema()(
        enabled,
        issuerAuthClaim,
        80551937543569765027552589160822318028
    );

    signal tmpAuthState;
    tmpAuthState <== getIdenState()(
        issuerAuthClaimsTreeRoot,
        issuerAuthRevTreeRoot,
        issuerAuthRootsTreeRoot
    );
    issuerAuthState <== tmpAuthState * enabled;

    checkClaimExists(issuerLevels)(
        enabled,
        issuerAuthClaim,
        issuerAuthClaimMtp,
        issuerAuthClaimsTreeRoot
    );

    checkClaimNotRevoked(issuerLevels)(
        enabled <== enabled,
        claim <== issuerAuthClaim,
        claimNonRevMTP <== issuerAuthClaimNonRevMtp,
        noAux <== issuerAuthClaimNonRevMtpNoAux,
        auxHi <== issuerAuthClaimNonRevMtpAuxHi,
        auxHv <== issuerAuthClaimNonRevMtpAuxHv,
        treeRoot <== issuerClaimNonRevRevTreeRoot
    );

    component issuerAuthPubKey = getPubKeyFromClaim();
    issuerAuthPubKey.claim <== issuerAuthClaim;

    verifyClaimSignature()(
        enabled,
        issuerClaim,
        issuerClaimSignatureR8x,
        issuerClaimSignatureR8y,
        issuerClaimSignatureS,
        issuerAuthPubKey.Ax,
        issuerAuthPubKey.Ay
    );
}

template mtpFlow(issuerLevels) {
    signal input enabled;
    signal input issuerClaim[8];
    signal input issuerClaimMtp[issuerLevels];
    signal input issuerClaimClaimsTreeRoot;
    signal input issuerClaimRevTreeRoot;
    signal input issuerClaimRootsTreeRoot;
    signal input issuerClaimIdenState;

    verifyClaimIssuance(issuerLevels)(
        enabled <== enabled,
        claim <== issuerClaim,
        claimIssuanceMtp <== issuerClaimMtp,
        claimIssuanceClaimsTreeRoot <== issuerClaimClaimsTreeRoot,
        claimIssuanceRevTreeRoot <== issuerClaimRevTreeRoot,
        claimIssuanceRootsTreeRoot <== issuerClaimRootsTreeRoot,
        claimIssuanceIdenState <== issuerClaimIdenState
    );
}