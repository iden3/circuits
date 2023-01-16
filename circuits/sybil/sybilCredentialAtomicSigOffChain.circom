pragma circom 2.0.0;

include "sybilUtils.circom";
include "../lib/utils/claimUtils.circom";
include "../lib/utils/treeUtils.circom";


template SybilCredentialAtomicSig(IssuerLevels, UserLevels, GistLevels) {
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

    signal input claimSchema;

  // claim of state secret stateSecret
    signal input stateCommitmentClaim[8];
    signal input stateCommitmentClaimMtp[UserLevels];
    signal input stateCommitmentClaimClaimsRoot;
    signal input stateCommitmentClaimRevRoot;
    signal input stateCommitmentClaimRootsRoot;
    signal input stateCommitmentClaimIdenState;
    
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
    signal input timestamp;

    // outputs
    signal output sybilID;
    signal output userID;

    component verifyIssuerClaim = VerifyIssuerClaim(IssuerLevels);
    for (var i=0; i<8; i++) { verifyIssuerClaim.issuerAuthClaim[i] <== issuerAuthClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyIssuerClaim.issuerAuthClaimMtp[i] <== issuerAuthClaimMtp[i]; }
    verifyIssuerClaim.issuerAuthClaimsRoot <== issuerAuthClaimsRoot;
    verifyIssuerClaim.issuerAuthRevRoot <== issuerAuthRevRoot;
    verifyIssuerClaim.issuerAuthRootsRoot <== issuerAuthRootsRoot;

    for (var i=0; i<IssuerLevels; i++) { verifyIssuerClaim.issuerAuthClaimNonRevMtp[i] <== issuerAuthClaimNonRevMtp[i]; }
    verifyIssuerClaim.issuerAuthClaimNonRevMtpNoAux <== issuerAuthClaimNonRevMtpNoAux;
    verifyIssuerClaim.issuerAuthClaimNonRevMtpAuxHi <== issuerAuthClaimNonRevMtpAuxHi;
    verifyIssuerClaim.issuerAuthClaimNonRevMtpAuxHv <== issuerAuthClaimNonRevMtpAuxHv;
    
    for (var i=0; i<8; i++) { verifyIssuerClaim.issuerClaim[i] <== issuerClaim[i]; }

    for (var i=0; i<IssuerLevels; i++) { verifyIssuerClaim.issuerClaimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    verifyIssuerClaim.issuerClaimNonRevMtpNoAux <== issuerClaimNonRevMtpNoAux;
    verifyIssuerClaim.issuerClaimNonRevMtpAuxHi <== issuerClaimNonRevMtpAuxHi;
    verifyIssuerClaim.issuerClaimNonRevMtpAuxHv <== issuerClaimNonRevMtpAuxHv;
    verifyIssuerClaim.issuerClaimNonRevClaimsRoot <== issuerClaimNonRevClaimsRoot;
    verifyIssuerClaim.issuerClaimNonRevRevRoot <== issuerClaimNonRevRevRoot;
    verifyIssuerClaim.issuerClaimNonRevRootsRoot <== issuerClaimNonRevRootsRoot;
    verifyIssuerClaim.issuerClaimNonRevState <== issuerClaimNonRevState;

    verifyIssuerClaim.issuerClaimSignatureR8x <== issuerClaimSignatureR8x;
    verifyIssuerClaim.issuerClaimSignatureR8y <== issuerClaimSignatureR8y;
    verifyIssuerClaim.issuerClaimSignatureS <== issuerClaimSignatureS;

    verifyIssuerClaim.claimSchema <== claimSchema;
    verifyIssuerClaim.profileNonce <== profileNonce;
    verifyIssuerClaim.userGenesisID <== userGenesisID;
    verifyIssuerClaim.claimSubjectProfileNonce <== claimSubjectProfileNonce;

    verifyIssuerClaim.timestamp  <== timestamp;
  
    verifyIssuerClaim.issuerAuthState ==> issuerAuthState;

    component verifyStateCommitment = VerifyStateCommitment(UserLevels, GistLevels);
    for (var i=0; i<8; i++) { verifyStateCommitment.claim[i] <== stateCommitmentClaim[i]; }
    for (var i=0; i<UserLevels; i++) { verifyStateCommitment.claimMtp[i] <== stateCommitmentClaimMtp[i]; }
    verifyStateCommitment.claimClaimsRoot <== stateCommitmentClaimClaimsRoot;
    verifyStateCommitment.claimRevRoot <== stateCommitmentClaimRevRoot;
    verifyStateCommitment.claimRootsRoot <== stateCommitmentClaimRootsRoot;
    verifyStateCommitment.claimIdenState <== stateCommitmentClaimIdenState;

    verifyStateCommitment.genesisID <== userGenesisID; 

    for (var i=0; i<GistLevels; i++) { verifyStateCommitment.gistMtp[i] <== gistMtp[i]; }
    verifyStateCommitment.gistRoot <== gistRoot;
    verifyStateCommitment.gistMtpAuxHi <== gistMtpAuxHi;
    verifyStateCommitment.gistMtpAuxHv <== gistMtpAuxHv;
    verifyStateCommitment.gistMtpNoAux <== gistMtpNoAux;
    
    component commClaimValueExtactor = getValueByIndex();
    for (var i=0; i<8; i++) { commClaimValueExtactor.claim[i] <== stateCommitmentClaim[i]; }
    commClaimValueExtactor.index <== 6; // secret value position stored in value slot 3 (which is index 7 our of 8)

    // Compute SybilId
    component sybilIDHasher = Poseidon(2);
    sybilIDHasher.inputs[0] <== commClaimValueExtactor.value;
    sybilIDHasher.inputs[1] <== crs;
    sybilID <== sybilIDHasher.out;

    // Compute profile.
    component selectProfile = SelectProfile();
    selectProfile.in <== userGenesisID;
    selectProfile.nonce <== profileNonce;
    userID <== selectProfile.out;
}

template VerifyIssuerClaim(IssuerLevels){
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

    signal input claimSchema;

    signal input timestamp;

    signal input userGenesisID;
    signal input profileNonce;
    signal input claimSubjectProfileNonce;

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
    component verifyClaimIdenState = checkIdenStateMatchesRoots();
    verifyClaimIdenState.claimsTreeRoot <== issuerClaimNonRevClaimsRoot;
    verifyClaimIdenState.revTreeRoot <== issuerClaimNonRevRevRoot;
    verifyClaimIdenState.rootsTreeRoot <== issuerClaimNonRevRootsRoot;
    verifyClaimIdenState.expectedState <== issuerClaimNonRevState;

    // Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== claimSchema;

    // Verify issuerClaim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i=0; i<8; i++) { claimExpirationCheck.claim[i] <== issuerClaim[i]; }
    claimExpirationCheck.timestamp <== timestamp;

    // Verify Issued to provided identity
    component claimIdCheck = verifyCredentialSubjectProfile();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== issuerClaim[i]; }
    claimIdCheck.id <== userGenesisID;
    claimIdCheck.nonce <== claimSubjectProfileNonce;
}