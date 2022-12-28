pragma circom 2.0.0;

include "sybilUtils.circom";
include "../lib/utils/claimUtils.circom";
include "../lib/utils/treeUtils.circom";


template SybilResCredentialAtomicQuerySigOffChain(IssuerLevels, HolderLevel, GistLevels) {
    // issuer auth proof of existence
    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimMtp[IssuerLevels];
    signal input issuerAuthClaimsRoot;
    signal input issuerAuthRevRoot;
    signal input issuerAuthRootsRoot;
    signal output issuerAuthState;

    // issuer auth claim non rev proof
    signal input issuerAuthClaimNonRevMtp[IssuerLevels];
    signal input issuerAuthClaimNonRevMtpNoAux;
    signal input issuerAuthClaimNonRevMtpAuxHi;
    signal input issuerAuthClaimNonRevMtpAuxHv;

    // claim issued by issuer to the user
    signal input issuerClaim[8];
    // issuerClaim non rev inputs
    signal input issuerClaimNonRevClaimsRoot;
    signal input issuerClaimNonRevRevRoot;
    signal input issuerClaimNonRevRootsRoot;

    signal input issuerClaimNonRevState;
    signal input issuerClaimNonRevMtp[IssuerLevels];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;

    // issuerClaim signature
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;

  // claim of state secret stateSecret
    signal input holderClaim[8];
    signal input holderClaimMtp[HolderLevel];
    signal input holderClaimClaimsRoot;
    signal input holderClaimRevRoot;
    signal input holderClaimRootsRoot;
    signal input holderClaimIdenState;
    
    // GIST and path to holderState
    signal input gistRoot;
    signal input gistMtp[GistLevels];
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;

    signal input crs;

    // identity
    signal input userGenesisID;
    signal input profileNonce;
    signal input claimSubjectProfileNonce;

    signal input requestID;
    signal input issuerID;
    signal input currentTimestamp;

    // inter signals
    signal issuerClaimHash;
    signal holderClaimValueHash;

    // outputs
    signal output sybilID;
    signal output userID;

    component verifyUniClaim = VerifyAndHashUniClaim(IssuerLevels);
    for (var i=0; i<8; i++) { verifyUniClaim.issuerAuthClaim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyUniClaim.issuerAuthClaimMtp[i] <== issuerAuthClaimMtp[i]; }
    verifyUniClaim.issuerAuthClaimsRoot <== issuerAuthClaimsRoot;
    verifyUniClaim.issuerAuthRevRoot <== issuerAuthRevRoot;
    verifyUniClaim.issuerAuthRootsRoot <== issuerAuthRootsRoot;

    for (var i=0; i<IssuerLevels; i++) { verifyUniClaim.issuerAuthClaimNonRevMtp[i] <== issuerAuthClaimNonRevMtp[i]; }
    verifyUniClaim.issuerAuthClaimNonRevMtpNoAux <== issuerAuthClaimNonRevMtpNoAux;
    verifyUniClaim.issuerAuthClaimNonRevMtpAuxHi <== issuerAuthClaimNonRevMtpAuxHi;
    verifyUniClaim.issuerAuthClaimNonRevMtpAuxHv <== issuerAuthClaimNonRevMtpAuxHv;
    
    for (var i=0; i<8; i++) { verifyUniClaim.issuerClaim[i] <== issuerClaim[i]; }

    for (var i=0; i<IssuerLevels; i++) { verifyUniClaim.issuerClaimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    verifyUniClaim.issuerClaimNonRevMtpNoAux <== issuerClaimNonRevMtpNoAux;
    verifyUniClaim.issuerClaimNonRevMtpAuxHi <== issuerClaimNonRevMtpAuxHi;
    verifyUniClaim.issuerClaimNonRevMtpAuxHv <== issuerClaimNonRevMtpAuxHv;
    verifyUniClaim.issuerClaimNonRevClaimsRoot <== issuerClaimNonRevClaimsRoot;
    verifyUniClaim.issuerClaimNonRevRevRoot <== issuerClaimNonRevRevRoot;
    verifyUniClaim.issuerClaimNonRevRootsRoot <== issuerClaimNonRevRootsRoot;
    verifyUniClaim.issuerClaimNonRevState <== issuerClaimNonRevState;

    verifyUniClaim.issuerClaimSignatureR8x <== issuerClaimSignatureR8x;
    verifyUniClaim.issuerClaimSignatureR8y <== issuerClaimSignatureR8y;
    verifyUniClaim.issuerClaimSignatureS <== issuerClaimSignatureS;

    component uniClaimSchemaHash = GetUniquenessSchemaHash();
    verifyUniClaim.issuerClaimSchema <== uniClaimSchemaHash.schemaHash;
    verifyUniClaim.profileNonce <== profileNonce;
    verifyUniClaim.userGenesisID <== userGenesisID;
    verifyUniClaim.claimSubjectProfileNonce <== claimSubjectProfileNonce;

    verifyUniClaim.currentTimestamp  <== currentTimestamp;
  
    verifyUniClaim.claimHash ==> issuerClaimHash;
    verifyUniClaim.issuerAuthState ==> issuerAuthState;

    component verifyStateSecret = VerifyAndExtractValStateSecret(HolderLevel, GistLevels);
    for (var i=0; i<8; i++) { verifyStateSecret.claim[i] <== holderClaim[i]; }
    for (var i=0; i<HolderLevel; i++) { verifyStateSecret.claimIssuanceMtp[i] <== holderClaimMtp[i]; }
    verifyStateSecret.claimIssuanceClaimsRoot <== holderClaimClaimsRoot;
    verifyStateSecret.claimIssuanceRevRoot <== holderClaimRevRoot;
    verifyStateSecret.claimIssuanceRootsRoot <== holderClaimRootsRoot;
    verifyStateSecret.claimIssuanceIdenState <== holderClaimIdenState;

    verifyStateSecret.genesisID <== userGenesisID; 

    for (var i=0; i<GistLevels; i++) { verifyStateSecret.gistMtp[i] <== gistMtp[i]; }
    verifyStateSecret.gistRoot <== gistRoot;
    verifyStateSecret.gistMtpAuxHi <== gistMtpAuxHi;
    verifyStateSecret.gistMtpAuxHv <== gistMtpAuxHv;
    verifyStateSecret.gistMtpNoAux <== gistMtpNoAux;

    verifyStateSecret.claimValueHash ==> holderClaimValueHash;
    
    // Compute SybilId
    component hash = Poseidon(3);
    hash.inputs[0] <== holderClaimValueHash;
    hash.inputs[1] <== issuerClaimHash;
    hash.inputs[2] <== crs;
    sybilID <== hash.out;

    // Compute profile.
    component selectProfile = SelectProfile();
    selectProfile.in <== userGenesisID;
    selectProfile.nonce <== profileNonce;
    userID <== selectProfile.out;
}


template VerifyAndHashUniClaim(IssuerLevels){
    signal input issuerAuthClaim[8];
    signal input issuerAuthClaimMtp[IssuerLevels];
    signal input issuerAuthClaimsRoot;
    signal input issuerAuthRevRoot;
    signal input issuerAuthRootsRoot;


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
    signal input issuerClaimNonRevClaimsRoot;
    signal input issuerClaimNonRevRevRoot;
    signal input issuerClaimNonRevRootsRoot;
    signal input issuerClaimNonRevState;

    // issuerClaim signature
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;

    signal input issuerClaimSchema;

    signal input currentTimestamp;

    signal input userGenesisID;
    signal input profileNonce;
    signal input claimSubjectProfileNonce;

    signal output claimHash;
    signal output issuerAuthState;

    //  Verify issued and not revoked
    var AUTH_SCHEMA_HASH  = 80551937543569765027552589160822318028;
    component issuerSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { issuerSchemaCheck.claim[i] <== issuerAuthClaim[i]; }
    issuerSchemaCheck.schema <== AUTH_SCHEMA_HASH;

    // IssuerAuthClaim proof of existence (isProofExist)
    component smtIssuerAuthClaimExists = checkClaimExists(IssuerLevels);
    for (var i=0; i<8; i++) { smtIssuerAuthClaimExists.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { smtIssuerAuthClaimExists.claimMTP[i] <== issuerAuthClaimMtp[i]; }
    smtIssuerAuthClaimExists.treeRoot <== issuerAuthClaimsRoot;

    component verifyIssuerAuthClaimNotRevoked = checkClaimNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyIssuerAuthClaimNotRevoked.claim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) {verifyIssuerAuthClaimNotRevoked.claimNonRevMTP[i] <== issuerAuthClaimNonRevMtp[i];}
    verifyIssuerAuthClaimNotRevoked.noAux <== issuerAuthClaimNonRevMtpNoAux;
    verifyIssuerAuthClaimNotRevoked.auxHi <== issuerAuthClaimNonRevMtpAuxHi;
    verifyIssuerAuthClaimNotRevoked.auxHv <== issuerAuthClaimNonRevMtpAuxHv;
    verifyIssuerAuthClaimNotRevoked.treeRoot <== issuerClaimNonRevRevRoot;
    verifyIssuerAuthClaimNotRevoked.enabled <== 1;

    // calculate issuerAuthState
    component issuerAuthStateComponent = getIdenState();
    issuerAuthStateComponent.claimsTreeRoot <== issuerAuthClaimsRoot;
    issuerAuthStateComponent.revTreeRoot <== issuerAuthRevRoot;
    issuerAuthStateComponent.rootsTreeRoot <== issuerAuthRootsRoot;

    issuerAuthState <== issuerAuthStateComponent.idenState;


    component issuerAuthPubKey = getPubKeyFromClaim();
    for (var i=0; i<8; i++){ issuerAuthPubKey.claim[i] <== issuerAuthClaim[i]; }

    // IssuerClaim  check signature
    component verifyClaimSig = verifyClaimSignature();
    for (var i=0; i<8; i++) { verifyClaimSig.claim[i] <== issuerClaim[i]; }
    verifyClaimSig.sigR8x <== issuerClaimSignatureR8x;
    verifyClaimSig.sigR8y <== issuerClaimSignatureR8y;
    verifyClaimSig.sigS <== issuerClaimSignatureS;
    verifyClaimSig.pubKeyX <== issuerAuthPubKey.Ax;
    verifyClaimSig.pubKeyY <== issuerAuthPubKey.Ay;

    // Check issuer-claim is not revoked (uniqueness claim is not revoled)
    component verifyClaimNotRevoked = checkClaimNotRevoked(IssuerLevels);
    for (var i=0; i<8; i++) { verifyClaimNotRevoked.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) {verifyClaimNotRevoked.claimNonRevMTP[i] <== issuerClaimNonRevMtp[i];}
    verifyClaimNotRevoked.noAux <== issuerClaimNonRevMtpNoAux;
    verifyClaimNotRevoked.auxHi <== issuerClaimNonRevMtpAuxHi;
    verifyClaimNotRevoked.auxHv <== issuerClaimNonRevMtpAuxHv;
    verifyClaimNotRevoked.treeRoot <== issuerClaimNonRevRevRoot;
    verifyClaimNotRevoked.enabled <== 1;

    // Verify issuer state includes issuerClaim
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.claimsTreeRoot <== issuerClaimNonRevClaimsRoot;
    verifyClaimIssuanceIdenState.revTreeRoot <== issuerClaimNonRevRevRoot;
    verifyClaimIssuanceIdenState.rootsTreeRoot <== issuerClaimNonRevRootsRoot;
    verifyClaimIssuanceIdenState.expectedState <== issuerClaimNonRevState;

    // Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== issuerClaimSchema;

    // Verify issuerClaim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i=0; i<8; i++) { claimExpirationCheck.claim[i] <== issuerClaim[i]; }
    claimExpirationCheck.timestamp <== currentTimestamp;

    // Verify Issued to provided identity
    component claimIdCheck = verifyCredentialSubjectProfile();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== issuerClaim[i]; }
    claimIdCheck.id <== userGenesisID;
    claimIdCheck.nonce <== claimSubjectProfileNonce;

    // Return hash of claim
    component hasher = getClaimHash();
    for (var i=0; i<8; i++) { hasher.claim[i] <== issuerClaim[i]; }
    claimHash <== hasher.hash;
}