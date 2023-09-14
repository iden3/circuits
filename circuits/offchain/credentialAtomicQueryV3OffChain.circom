pragma circom 2.1.5;

include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/mux4.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/query/comparators.circom";
include "../auth/authV2.circom";
include "../lib/query/query.circom";
include "../lib/query/nullify.circom";
include "../lib/utils/idUtils.circom";

template credentialAtomicQueryV3OffChain(issuerLevels, claimLevels, valueArraySize) {
    // common outputs for Sig and MTP
    signal output merklized;
    signal output userID;

    // common inputs for Sig and MTP
    signal input proofType;  // sig 0, mtp 1
    signal input requestID;
    signal input userGenesisID;
    signal input profileNonce;
    signal input claimSubjectProfileNonce; // nonce of the profile that claim is issued to, 0 if claim is issued to genesisID

    signal input issuerID;
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

    signal input issuerClaim[8];

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

    // Sig specific outputs
    signal output issuerAuthState;

    // Modifier/Computation Operator output ($sd, $nullify)
    signal output operatorOutput;

    /////////////////////////////////////////////////////////////////
    // Claim Verification (id, schema, expiration, issuance, revocation)
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

    /////////////////////////////////////////////////////////////////
    // Field Path and Value Verification
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
    // Query Operator Processing
    /////////////////////////////////////////////////////////////////

    // verify query
    signal querySatisfied <== Query(valueArraySize)(
        in <== fieldValue,
        value <== value,
        operator <== operator
    );

    querySatisfied === 1;

    /////////////////////////////////////////////////////////////////
    // Modifier/Computation Operators Processing
    /////////////////////////////////////////////////////////////////

    // selective disclosure calculation
    // no need to calc anything, fieldValue is just passed as an output

    // nullifier calculation
    signal isNullifyOp <== IsEqual()([operator, 17]);
    signal nullifier <== Nullify()(
        isNullifyOp,
        userGenesisID,
        claimSubjectProfileNonce,
        fieldValue,
        value[0] // get csr from value array
    );

    /////////////////////////////////////////////////////////////////
    // Operator Output Preparation
    /////////////////////////////////////////////////////////////////

    // parse operator to bits
    signal opBits[5] <== Num2Bits(5)(operator); // values 0-15 are query operators, 16-31 - modifiers/computations

    // output value calculation
    signal modifierOutput <== Mux4()(
        s <== [opBits[0], opBits[1], opBits[2], opBits[3]],

        c <== [
            fieldValue, // 16 - selective disclosure (16-16 = index 0)
            nullifier, // 17 - nullify (17-16 = index 1)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 // 18-31 - not used
        ]
    );

    // output value only if modifier operation was selected
    operatorOutput <== Mux1()(
        c <== [0, modifierOutput], // output 0 for non-modifier operations
        s <== opBits[4] // operator values 0-15 are query operators, 16-31 - modifiers/computations
    );

    /////////////////////////////////////////////////////////////////
    // ProfileID calculation
    /////////////////////////////////////////////////////////////////
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
