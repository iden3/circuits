pragma circom 2.1.5;

include "../../node_modules/circomlib/circuits/gates.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/mux4.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../auth/authV2.circom";
include "../lib/linked/linkId.circom";
include "../lib/query/processQueryWithModifiers.circom";
include "../lib/utils/nullify.circom";
include "../lib/utils/idUtils.circom";
include "../lib/utils/safeOne.circom";
include "../lib/utils/tags-managing.circom";

template credentialAtomicQueryV3OffChain(issuerLevels, claimLevels, maxValueArraySize) {
    // common outputs for Sig and MTP
    signal output {binary} merklized;
    signal output userID;

    // common inputs for Sig and MTP
    signal input proofType;  // sig 1, mtp 2
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

    // Modifier/Computation Operator output ($sd)
    signal output operatorOutput;

    // get safe one values to be used in ForceEqualIfEnabled
    signal {binary} one <== SafeOne()(userGenesisID);

    signal safeUserGenesisID <== ForceMaxbit(248)(userGenesisID);

    /////////////////////////////////////////////////////////////////
    // Claim Verification (id, schema, expiration, issuance, revocation)
    /////////////////////////////////////////////////////////////////

    component issuerClaimHeader = getClaimHeader();
    issuerClaimHeader.claim <== issuerClaim;

    // Check issuerClaim is issued to provided identity
    verifyCredentialSubjectProfile()(
        one,
        issuerClaim,
        issuerClaimHeader.claimFlags,
        safeUserGenesisID,
        claimSubjectProfileNonce
    ); // 1236 constraints

    // Verify issuerClaim schema
    verifyCredentialSchema()(one, issuerClaimHeader.schema, claimSchema); // 3 constraints

    // verify issuerClaim expiration time
    verifyExpirationTime()(issuerClaimHeader.claimFlags[3], issuerClaim, timestamp); // 322 constraints
    
    signal {binary} isSig  <== IsEqual()([proofType, 1]);
    signal {binary} isMTP <== IsEqual()([proofType, 2]);
    signal validProofType <== OR()(isSig, isMTP);
    ForceEqualIfEnabled()(one, [validProofType, 1]);

    signal issuerClaimHash, issuerClaimHi, issuerClaimHv;
    (issuerClaimHash, issuerClaimHi, issuerClaimHv) <== getClaimHash()(issuerClaim);

    sigFlow(issuerLevels)(
        enabled <== isSig,
        issuerAuthClaim <== issuerAuthClaim,
        issuerAuthClaimNonRevMtp <== issuerAuthClaimNonRevMtp,
        issuerAuthClaimNonRevMtpNoAux <== issuerAuthClaimNonRevMtpNoAux,
        issuerAuthClaimNonRevMtpAuxHi <== issuerAuthClaimNonRevMtpAuxHi,
        issuerAuthClaimNonRevMtpAuxHv <== issuerAuthClaimNonRevMtpAuxHv,
        issuerClaimNonRevRevTreeRoot <== issuerClaimNonRevRevTreeRoot,
        issuerClaimHash <== issuerClaimHash,
        issuerClaimSignatureR8x <== issuerClaimSignatureR8x,
        issuerClaimSignatureR8y <== issuerClaimSignatureR8y,
        issuerClaimSignatureS <== issuerClaimSignatureS
    ); // 16237 constraints

    signal issuerAuthClaimHi, issuerAuthClaimHv;
	(issuerAuthClaimHi, issuerAuthClaimHv) <== getClaimHiHv()(issuerAuthClaim);

    signal _claimHi, _claimHv, _claimIssuanceMtp[issuerLevels],
        _claimIssuanceClaimsTreeRoot, _claimIssuanceRevTreeRoot,
        _claimIssuanceRootsTreeRoot, _claimIssuanceIdenState;

    // switch between claim and authClaim issuance proof depending if Sig or MTP proof is provided
    issuerState <== Mux1()([issuerClaimIdenState, issuerAuthState], isSig);
    _claimHi <== Mux1()([issuerClaimHi, issuerAuthClaimHi], isSig);
    _claimHv <== Mux1()([issuerClaimHv, issuerAuthClaimHv], isSig);
    for (var i = 0; i < issuerLevels; i++) {
        _claimIssuanceMtp[i] <== Mux1()([issuerClaimMtp[i], issuerAuthClaimMtp[i]], isSig);
    }
    _claimIssuanceClaimsTreeRoot <== Mux1()([issuerClaimClaimsTreeRoot, issuerAuthClaimsTreeRoot], isSig);
    _claimIssuanceRevTreeRoot <== Mux1()([issuerClaimRevTreeRoot, issuerAuthRevTreeRoot], isSig);
    _claimIssuanceRootsTreeRoot <== Mux1()([issuerClaimRootsTreeRoot, issuerAuthRootsTreeRoot], isSig);
    _claimIssuanceIdenState <== Mux1()([issuerClaimIdenState, issuerAuthState], isSig);

    // Verify issuance of claim in case of MTP proof OR issuance of auth claim in case of Sig proof
    verifyClaimIssuance(issuerLevels)(
        enabled <== one,
        claimHi <== _claimHi,
        claimHv <== _claimHv,
        claimIssuanceMtp <== _claimIssuanceMtp,
        claimIssuanceClaimsTreeRoot <== _claimIssuanceClaimsTreeRoot,
        claimIssuanceRevTreeRoot <== _claimIssuanceRevTreeRoot,
        claimIssuanceRootsTreeRoot <== _claimIssuanceRootsTreeRoot,
        claimIssuanceIdenState <== issuerState
    ); // 11184 constraints

    signal {binary} safeIsRevocationChecked <== ForceBinary()(isRevocationChecked);

    // check claim is not revoked
    checkClaimNotRevoked(issuerLevels)(
        enabled <== safeIsRevocationChecked,
        claim <== issuerClaim,
        claimNonRevMTP <== issuerClaimNonRevMtp,
        noAux <== issuerClaimNonRevMtpNoAux,
        auxHi <== issuerClaimNonRevMtpAuxHi,
        auxHv <== issuerClaimNonRevMtpAuxHv,
        treeRoot <== issuerClaimNonRevRevTreeRoot
    ); // 11763 constraints

    // check issuer non revocation state only if we need it:
    // 1. if Sig proof is provided we need to check non revocation of authClaim always
    // AND non revocation of issuerClaim only if isRevocationChecked = 1
    // 2. if MTP proof is provided we need to check non revocation of claim only if isRevocationChecked = 1
    signal {binary} checkIssuerClaimNonRevState <== OR()(isSig, safeIsRevocationChecked);

    // verify issuer state for claim non-revocation proof
    checkIdenStateMatchesRoots()(
        checkIssuerClaimNonRevState,
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
    merklize.claimFlags <== issuerClaimHeader.claimFlags;

    merklized <== merklize.flag;

    /////////////////////////////////////////////////////////////////
    // Process Query with Modifiers
    /////////////////////////////////////////////////////////////////
    // output value only if modifier operation was selected
    operatorOutput <== ProcessQueryWithModifiers(claimLevels, maxValueArraySize)(
        one,
        claimPathMtp,
        claimPathMtpNoAux,
        claimPathMtpAuxHi,
        claimPathMtpAuxHv,
        claimPathKey,
        claimPathValue,
        slotIndex,
        operator,
        value,
        valueArraySize,
        issuerClaim,
        merklized,
        merklize.out
    );

    // nullifier calculation
    nullifier <== Nullify()(
        safeUserGenesisID,
        claimSubjectProfileNonce,
        claimSchema,
        verifierID,
        nullifierSessionID
    ); // 330 constraints

    /////////////////////////////////////////////////////////////////
    // ProfileID calculation
    /////////////////////////////////////////////////////////////////
    userID <== SelectProfile()(safeUserGenesisID, profileNonce); // 1231 constraints

    /////////////////////////////////////////////////////////////////
    // Link ID calculation
    /////////////////////////////////////////////////////////////////
    linkID <== LinkID()(issuerClaimHash, linkNonce); // 243 constraints
}

template sigFlow(issuerLevels) {
    signal input {binary} enabled;
    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimNonRevMtp[issuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;
    signal input issuerClaimNonRevRevTreeRoot;
    signal input issuerClaimHash;
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;

    component issuerAuthClaimHeader = getClaimHeader();
    issuerAuthClaimHeader.claim <== issuerAuthClaim;

    verifyCredentialSchema()(
        enabled,
        issuerAuthClaimHeader.schema,
        80551937543569765027552589160822318028
    );

    // check authClaim is not revoked
    checkClaimNotRevoked(issuerLevels)(
        enabled <== enabled,
        claim <== issuerAuthClaim,
        claimNonRevMTP <== issuerAuthClaimNonRevMtp,
        noAux <== issuerAuthClaimNonRevMtpNoAux,
        auxHi <== issuerAuthClaimNonRevMtpAuxHi,
        auxHv <== issuerAuthClaimNonRevMtpAuxHv,
        treeRoot <== issuerClaimNonRevRevTreeRoot // the same value as for the claim non-revocation check
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

    // explicitly state that these signals are not used and it's ok
    for (var i=0; i<32; i++) {
        _ <== issuerAuthClaimHeader.claimFlags[i];
    }
}
