pragma circom 2.1.1;
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../lib/query/comparators.circom";
include "../auth/authV3.circom";
include "../lib/query/query.circom";
include "../lib/utils/idUtils.circom";
include "../lib/utils/spongeHash.circom";
include "../offchain/credentialAtomicQueryV3OffChain.circom";
include "../lib/utils/queryHash.circom";
include "../lib/utils/tags-managing.circom";

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
maxValueArraySize - Number of elements in comparison array for in/notin operation if level = 3 number of values for
comparison ["1", "2", "3"]
onChainLevels - Merkle tree depth level for Auth claim on-chain
*/
template credentialAtomicQueryV3OnChain(issuerLevels, claimLevels, maxValueArraySize, idOwnershipLevels, onChainLevels) {
    // userID output signal will be assigned with ProfileID SelectProfile(UserGenesisID, nonce)
    // unless nonce == 0, in which case userID will be assigned with userGenesisID
    signal output userID;

    // circuits query Hash
    signal output circuitQueryHash;
    
    signal input proofType;  // sig 1, mtp 2

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

    signal input claimPathMtp[claimLevels];
    signal input claimPathMtpNoAux; // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
    signal input claimPathMtpAuxHi; // 0 for inclusion proof
    signal input claimPathMtpAuxHv; // 0 for inclusion proof
    signal input claimPathKey; // hash of path in merklized json-ld document
    signal input claimPathValue; // value in this path in merklized json-ld document

    signal input slotIndex;
    signal input operator;
    signal input value[maxValueArraySize];
    signal input valueArraySize;

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
    signal input issuerAuthState;
    signal input issuerAuthClaimNonRevMtp[issuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;

    // Issuer State to be checked outside of the circuit
    // in case of MTP proof issuerState = issuerClaimIdenState
    // in case of Sig proof issuerState = issuerAuthState
    signal output issuerState;

    // Private random nonce, used to generate LinkID
    signal input linkNonce;
    signal output linkID;

    // Identifier of the verifier
    signal input verifierID;

    // nullifier input & output signals
    signal input nullifierSessionID;
    signal output nullifier;

    // Modifier/Computation Operator output ($sd, $nullify)
    signal output operatorOutput;

    // Enabled/disable checkAuthV3 verification
    signal input isBJJAuthEnabled;

    // flag indicates if merklized flag set in issuer claim (if set MTP is used to verify that
    // claimPathValue and claimPathKey are stored in the merkle tree) and verification is performed
    // on root stored in the index or value slot
    // if it is not set verification is performed on according to the slotIndex. Value selected from the
    // provided slot. For example if slotIndex is `1` value gets from `i_1` slot. If `4` from `v_1`.
    signal {binary} merklized;

    /////////////////////////////////////////////////////////////////
    // Auth check
    /////////////////////////////////////////////////////////////////

    signal {binary} safeIsBJJAuthEnabled <== AddBinaryTag()(isBJJAuthEnabled);

    ForceEqualIfEnabled()(NOT()(safeIsBJJAuthEnabled), [profileNonce, 0]);

    checkAuthV3(idOwnershipLevels, onChainLevels)(
        safeIsBJJAuthEnabled, // enabled
        userGenesisID,
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
    // Claim checks
    /////////////////////////////////////////////////////////////////

    (merklized, userID, issuerState, linkID, nullifier, operatorOutput) <== credentialAtomicQueryV3OffChain(issuerLevels, claimLevels, maxValueArraySize)(
        proofType <== proofType,
        requestID <== requestID,
        userGenesisID <== userGenesisID,
        profileNonce <== profileNonce,
        claimSubjectProfileNonce <== claimSubjectProfileNonce,
        issuerID <== issuerID,
        isRevocationChecked <== isRevocationChecked,
        issuerClaimNonRevMtp <== issuerClaimNonRevMtp,
        issuerClaimNonRevMtpNoAux <== issuerClaimNonRevMtpNoAux,
        issuerClaimNonRevMtpAuxHi <== issuerClaimNonRevMtpAuxHi,
        issuerClaimNonRevMtpAuxHv <== issuerClaimNonRevMtpAuxHv,
        issuerClaimNonRevClaimsTreeRoot <== issuerClaimNonRevClaimsTreeRoot,
        issuerClaimNonRevRevTreeRoot <== issuerClaimNonRevRevTreeRoot,
        issuerClaimNonRevRootsTreeRoot <== issuerClaimNonRevRootsTreeRoot,
        issuerClaimNonRevState <== issuerClaimNonRevState,
        timestamp <== timestamp,
        claimSchema <== claimSchema,
        claimPathMtp <== claimPathMtp,
        claimPathMtpNoAux <== claimPathMtpNoAux,
        claimPathMtpAuxHi <== claimPathMtpAuxHi,
        claimPathMtpAuxHv <== claimPathMtpAuxHv,
        claimPathKey <== claimPathKey,
        claimPathValue <== claimPathValue,
        slotIndex <== slotIndex,
        operator <== operator,
        value <== value,
        valueArraySize <== valueArraySize,
        issuerClaim <== issuerClaim,
        issuerClaimMtp <== issuerClaimMtp,
        issuerClaimClaimsTreeRoot <== issuerClaimClaimsTreeRoot,
        issuerClaimRevTreeRoot <== issuerClaimRevTreeRoot,
        issuerClaimRootsTreeRoot <== issuerClaimRootsTreeRoot,
        issuerClaimIdenState <== issuerClaimIdenState,
        issuerAuthClaim <== issuerAuthClaim,
        issuerAuthClaimMtp <== issuerAuthClaimMtp,
        issuerAuthClaimsTreeRoot <== issuerAuthClaimsTreeRoot,
        issuerAuthRevTreeRoot <== issuerAuthRevTreeRoot,
        issuerAuthRootsTreeRoot <== issuerAuthRootsTreeRoot,
        issuerAuthState <== issuerAuthState,
        issuerAuthClaimNonRevMtp <== issuerAuthClaimNonRevMtp,
        issuerAuthClaimNonRevMtpNoAux <== issuerAuthClaimNonRevMtpNoAux,
        issuerAuthClaimNonRevMtpAuxHi <== issuerAuthClaimNonRevMtpAuxHi,
        issuerAuthClaimNonRevMtpAuxHv <== issuerAuthClaimNonRevMtpAuxHv,
        issuerClaimSignatureR8x <== issuerClaimSignatureR8x,
        issuerClaimSignatureR8y <== issuerClaimSignatureR8y,
        issuerClaimSignatureS <== issuerClaimSignatureS,
        linkNonce <== linkNonce,
        verifierID <== verifierID,
        nullifierSessionID <== nullifierSessionID
    );

    /////////////////////////////////////////////////////////////////
    // Verify query hash matches
    /////////////////////////////////////////////////////////////////

    circuitQueryHash <== QueryHash(maxValueArraySize)(
        value,
        claimSchema,
        slotIndex,
        operator,
        claimPathKey,
        valueArraySize,
        merklized,
        isRevocationChecked,
        verifierID,
        nullifierSessionID
    );

}
