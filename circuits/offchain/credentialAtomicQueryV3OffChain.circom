pragma circom 2.1.5;

include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/mux4.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../auth/authV2.circom";
include "../lib/linked/linkId.circom";
include "../lib/query/comparators.circom";
include "../lib/query/modifiers.circom";
include "../lib/query/nullify.circom";
include "../lib/query/query.circom";
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

    // Private random nonce, used to generate LinkID
    signal input linkNonce;
    signal output linkID;

    // Identifier of the verifier
    signal input verifierID;

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
    ); // 1744 constraints

    // Verify issuerClaim schema
    verifyCredentialSchema()(1, issuerClaim, claimSchema); // 254 constraints

    // verify issuerClaim expiration time
    verifyExpirationTime()(issuerClaim, timestamp); // 574 constraints
    
    signal isSig;
    signal isMTP;
    isSig  <== 1 - proofType;
    isMTP <== proofType;
    isSig * isMTP === 0;

    signal issuerClaimHash, issuerClaimHi, issuerClaimHv;
    (issuerClaimHash, issuerClaimHi, issuerClaimHv) <== getClaimHash()(issuerClaim);

    sigFlow(issuerLevels)(
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
        issuerClaimHash <== issuerClaimHash,
        issuerClaimSignatureR8x <== issuerClaimSignatureR8x,
        issuerClaimSignatureR8y <== issuerClaimSignatureR8y,
        issuerClaimSignatureS <== issuerClaimSignatureS
    ); // 28265 constraints

    // TODO: move calc outside of the circuit
    signal tmpAuthState;
    tmpAuthState <== getIdenState()(
        issuerAuthClaimsTreeRoot,
        issuerAuthRevTreeRoot,
        issuerAuthRootsTreeRoot
    );
    issuerAuthState <== tmpAuthState * isSig;

//    mtpFlow(issuerLevels)(
//        enabled <== isMTP,
//        issuerClaimHi <== issuerClaimHi,
//        issuerClaimHv <== issuerClaimHv,
//        issuerClaimMtp <== issuerClaimMtp,
//        issuerClaimClaimsTreeRoot <== issuerClaimClaimsTreeRoot,
//        issuerClaimRevTreeRoot <== issuerClaimRevTreeRoot,
//        issuerClaimRootsTreeRoot <== issuerClaimRootsTreeRoot,
//        issuerClaimIdenState <== issuerClaimIdenState
//    ); // 11436 constraints

    signal issuerAuthClaimHi, issuerAuthClaimHv;
	(issuerAuthClaimHi, issuerAuthClaimHv) <== getClaimHiHv()(issuerAuthClaim);

    signal tmpClaimHi, tmpClaimHv, tmpClaimIssuanceMtp[issuerLevels],
        tmpClaimIssuanceClaimsTreeRoot, tmpClaimIssuanceRevTreeRoot,
        tmpClaimIssuanceRootsTreeRoot, tmpClaimIssuanceIdenState;

    tmpClaimHi <== Mux1()([issuerClaimHi, issuerAuthClaimHi], isSig);
    tmpClaimHv <== Mux1()([issuerClaimHv, issuerAuthClaimHv], isSig);
    for (var i = 0; i < issuerLevels; i++) {
        tmpClaimIssuanceMtp[i] <== Mux1()([issuerClaimMtp[i], issuerAuthClaimMtp[i]], isSig);
    }
    tmpClaimIssuanceClaimsTreeRoot <== Mux1()([issuerClaimClaimsTreeRoot, issuerAuthClaimsTreeRoot], isSig);
    tmpClaimIssuanceRevTreeRoot <== Mux1()([issuerClaimRevTreeRoot, issuerAuthRevTreeRoot], isSig);
    tmpClaimIssuanceRootsTreeRoot <== Mux1()([issuerClaimRootsTreeRoot, issuerAuthRootsTreeRoot], isSig);
    tmpClaimIssuanceIdenState <== Mux1()([issuerClaimIdenState, issuerAuthState], isSig);

    // Verify issuance of claim in case of MTP proof OR issuance of auth claim in case of Sig proof
    verifyClaimIssuance(issuerLevels)(
        enabled <== 1,
        claimHi <== tmpClaimHi,
        claimHv <== tmpClaimHv,
        claimIssuanceMtp <== tmpClaimIssuanceMtp,
        claimIssuanceClaimsTreeRoot <== tmpClaimIssuanceClaimsTreeRoot,
        claimIssuanceRevTreeRoot <== tmpClaimIssuanceRevTreeRoot,
        claimIssuanceRootsTreeRoot <== tmpClaimIssuanceRootsTreeRoot,
        claimIssuanceIdenState <== tmpClaimIssuanceIdenState
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
    ); // 11763 constraints

    // verify issuer state for claim non-revocation proof
    checkIdenStateMatchesRoots()(
        1,
        issuerClaimNonRevClaimsTreeRoot,
        issuerClaimNonRevRevTreeRoot,
        issuerClaimNonRevRootsTreeRoot,
        issuerClaimNonRevState
    ); // 261 constraints

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
    ); // 9585 constraints

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
    // 2482 constraints (Query+LessThan+ForceEqualIfEnabled)
    signal querySatisfied <== Query(valueArraySize)(
        in <== fieldValue,
        value <== value,
        operator <== operator
    );

    signal isQueryOp <== LessThan(5)([operator, 16]);
    ForceEqualIfEnabled()(
        isQueryOp,
        [querySatisfied, 1]
    );

    /////////////////////////////////////////////////////////////////
    // Modifier/Computation Operators Processing
    /////////////////////////////////////////////////////////////////

    // selective disclosure
    // no need to calc anything, fieldValue is just passed as an output

    // nullifier calculation
    signal nullifier <== Nullify()(
        userGenesisID,
        claimSubjectProfileNonce,
        claimSchema,
        fieldValue,
        verifierID,
        value[0] // get csr from value array
    ); // 300 constraints

    /////////////////////////////////////////////////////////////////
    // Modifier Operator Validation & Output Preparation
    /////////////////////////////////////////////////////////////////

    // output value only if modifier operation was selected
    operatorOutput <== modifierValidatorOutputSelector()(
        operator <== operator,
        modifierOutputs <== [
            fieldValue, // 16 - selective disclosure (16-16 = index 0)
            nullifier, // 17 - nullify (17-16 = index 1)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 // 18-31 - not used
        ]
    );

    /////////////////////////////////////////////////////////////////
    // ProfileID calculation
    /////////////////////////////////////////////////////////////////
    userID <== SelectProfile()(userGenesisID, profileNonce); // 1485 constraints

    /////////////////////////////////////////////////////////////////
    // Link ID calculation
    /////////////////////////////////////////////////////////////////
    linkID <== LinkID()(issuerClaim, linkNonce); // 1077 constraints
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
    signal input issuerClaimHash;
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;

    verifyCredentialSchema()(
        enabled,
        issuerAuthClaim,
        80551937543569765027552589160822318028
    );

    checkClaimNotRevoked(issuerLevels)(
        enabled <== enabled,
        claim <== issuerAuthClaim,
        claimNonRevMTP <== issuerAuthClaimNonRevMtp,
        noAux <== issuerAuthClaimNonRevMtpNoAux,
        auxHi <== issuerAuthClaimNonRevMtpAuxHi,
        auxHv <== issuerAuthClaimNonRevMtpAuxHv,
        treeRoot <== issuerClaimNonRevRevTreeRoot // TODO: can we reuse issuerAuthRevTreeRoot & state here?
    ); // 11763 constraints

    component issuerAuthPubKey = getPubKeyFromClaim();
    issuerAuthPubKey.claim <== issuerAuthClaim;

    verifyClaimSignature()(
        enabled,
        issuerClaimHash,
        issuerClaimSignatureR8x,
        issuerClaimSignatureR8y,
        issuerClaimSignatureS,
        issuerAuthPubKey.Ax,
        issuerAuthPubKey.Ay
    ); // 4217 constraints
}

template mtpFlow(issuerLevels) {
    signal input enabled;
    signal input issuerClaimHi;
    signal input issuerClaimHv;
    signal input issuerClaimMtp[issuerLevels];
    signal input issuerClaimClaimsTreeRoot;
    signal input issuerClaimRevTreeRoot;
    signal input issuerClaimRootsTreeRoot;
    signal input issuerClaimIdenState;

    verifyClaimIssuance(issuerLevels)(
        enabled <== enabled,
        claimHi <== issuerClaimHi,
        claimHv <== issuerClaimHv,
        claimIssuanceMtp <== issuerClaimMtp,
        claimIssuanceClaimsTreeRoot <== issuerClaimClaimsTreeRoot,
        claimIssuanceRevTreeRoot <== issuerClaimRevTreeRoot,
        claimIssuanceRootsTreeRoot <== issuerClaimRootsTreeRoot,
        claimIssuanceIdenState <== issuerClaimIdenState
    );
}
