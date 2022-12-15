pragma circom 2.0.0;



// Public
// ---------
// IssuerState (states, 1-state: for the issuance of the kyc-claim, 2-state: latest state of the issuer)
// kycClaimSchemaID (~claim_of_uniqueness)
// stateCommitmentSchemaID - need to be defined
// Reference GIST 
// CRS                          V
//


// Private
// ---------
// uniquenessClaim              V
// identiifer/userGenesisID     V
// profileNonce                 V
// stateCommitmentSecret        V


// Outputs
// --------
// ProfileID
// SybilID

template SybilResCredentialAtomicQueryMTPOffChain(IssuerLevels, ClaimLevels, valueArraySize, gistLevels) {

    // claim of uniqueness 
    signal input issuerClaim[8];
    signal input issuerClaimMtp[IssuerLevels];
    signal input issuerClaimClaimsTreeRoot;
    signal input issuerClaimRevTreeRoot;
    signal input issuerClaimRootsTreeRoot;
    signal input issuerClaimIdenState;

    signal input issuerClaimNonRevMtp[IssuerLevels];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;
    signal input issuerClaimNonRevClaimsTreeRoot;
    signal input issuerClaimNonRevRevTreeRoot;
    signal input issuerClaimNonRevRootsTreeRoot;
    signal input issuerClaimNonRevState;

    signal input issuerClaimSchema;

    // claim of state secret stateSecret
    signal input holderClaim[8];
    signal input holderClaimMtp[IssuerLevels];
    signal input holderClaimClaimsTreeRoot;
    signal input holderClaimRevTreeRoot;
    signal input holderClaimRootsTreeRoot;
    signal input holderClaimIdenState;

    // GIST and path to holderState
    signal input gist;
    signal input gistMtp[GistLevels];

    signal input crs;

    signal input userGenesisID;
    signal input profileNonce;

    signal output userId;
    signal output sybilId;

    // mid signal
    signal uniClaimHash;
    signal secret;


    component verifyUniClaim = VerifyAndHashUniClaim(IssuerLevels);
    uniClaimHash <== verifyUniClaim.hash;
    // signal input issuerClaim[8];
    // signal input issuerClaimMtp[IssuerLevels];
    // signal input issuerClaimClaimsTreeRoot;
    // signal input issuerClaimRevTreeRoot;
    // signal input issuerClaimRootsTreeRoot;
    // signal input issuerClaimIdenState;
    // signal input issuerClaimNonRevMtp[IssuerLevels];
    // signal input issuerClaimNonRevMtpNoAux;
    // signal input issuerClaimNonRevMtpAuxHi;
    // signal input issuerClaimNonRevMtpAuxHv;
    // signal input issuerClaimNonRevClaimsTreeRoot;
    // signal input issuerClaimNonRevRevTreeRoot;
    // signal input issuerClaimNonRevRootsTreeRoot;
    // signal input issuerClaimNonRevState;
    // signal input issuerClaimSchema;
    // signal input userGenesisID;
    // signal input profileNonce;

    component verifyStateSecret = VerifyAndExtractValStateSecret(IssuerLevels, gistLevels)
    secret <== verifyStateSecret.secret;

    // Compute SybilId
    component computeSybilID = ComputeSybilID();
    computeSybilID.crs <== crs;
    computeSybilID.state_cm_secret <== secret;
    computeSybilID.unique_claim <== uniClaimHash;
    sybilId <== computeSybilID,out;

    // Compute UserId
    component selectProfile = SelectProfile();
    selectProfile.in <== userGenesisID;
    selectProfile.nonce <== profileNonce;
    userId <== selectProfile.out;
}


template VerifyAndHashUniClaim(IssuerLevels){
    signal input issuerClaim[8];
    signal input issuerClaimMtp[IssuerLevels];
    signal input issuerClaimClaimsTreeRoot;
    signal input issuerClaimRevTreeRoot;
    signal input issuerClaimRootsTreeRoot;
    signal input issuerClaimIdenState;

    signal input issuerClaimNonRevMtp[IssuerLevels];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;
    signal input issuerClaimNonRevClaimsTreeRoot;
    signal input issuerClaimNonRevRevTreeRoot;
    signal input issuerClaimNonRevRootsTreeRoot;
    signal input issuerClaimNonRevState;

    signal input issuerClaimSchema;

    signal input userID;
    signal input profileNonce;

    signal output hash;

    // (1) Verify claim issued
    component vci = verifyClaimIssuanceNonRev(IssuerLevels);
    for (var i=0; i<8; i++) { vci.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { vci.claimIssuanceMtp[i] <== issuerClaimMtp[i]; }
    vci.claimIssuanceClaimsTreeRoot <== issuerClaimClaimsTreeRoot;
    vci.claimIssuanceRevTreeRoot <== issuerClaimRevTreeRoot;
    vci.claimIssuanceRootsTreeRoot <== issuerClaimRootsTreeRoot;
    vci.claimIssuanceIdenState <== issuerClaimIdenState;

    // (2) And non revocation status
    for (var i=0; i<IssuerLevels; i++) { vci.claimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    vci.claimNonRevMtpNoAux <== issuerClaimNonRevMtpNoAux;
    vci.claimNonRevMtpAuxHi <== issuerClaimNonRevMtpAuxHi;
    vci.claimNonRevMtpAuxHv <== issuerClaimNonRevMtpAuxHv;
    vci.claimNonRevIssuerClaimsTreeRoot <== issuerClaimNonRevClaimsTreeRoot;
    vci.claimNonRevIssuerRevTreeRoot <== issuerClaimNonRevRevTreeRoot;
    vci.claimNonRevIssuerRootsTreeRoot <== issuerClaimNonRevRootsTreeRoot;
    vci.claimNonRevIssuerState <== issuerClaimNonRevState;

    // (3) Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== issuerClaimSchema;

    // (4) Check claim is issued to provided identity
    component claimIdCheck = verifyCredentialSubjectProfile();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== issuerClaim[i]; }
    claimIdCheck.id <== userID;
    claimIdCheck.nonce <== profileNonce;

    // (5) Get claim hash
    component claimHash = getClaimHash()
    claimHash.claim <== issuerClaim;
    hash <== claimHash.hash;
}

template VerifyAndExtractValStateSecret(IssuerLevels, gistLevels){
    signal output secret;
    // (1) Verify claim is included in claims tree root
    component claimIssuanceCheck = checkClaimExists(IssuerLevels);
    for (var i=0; i<8; i++) { claimIssuanceCheck.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) { claimIssuanceCheck.claimMTP[i] <== claimIssuanceMtp[i]; }
    claimIssuanceCheck.treeRoot <== claimIssuanceClaimsTreeRoot;

    // verify state includes claims tree
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.claimsTreeRoot <== claimIssuanceClaimsTreeRoot;
    verifyClaimIssuanceIdenState.revTreeRoot <== claimIssuanceRevTreeRoot;
    verifyClaimIssuanceIdenState.rootsTreeRoot <== claimIssuanceRootsTreeRoot;
    verifyClaimIssuanceIdenState.expectedState <== claimIssuanceIdenState;

    // (2) Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== issuerClaim[i]; }
    claimSchemaCheck.schema <== issuerClaimSchema;

    // (3) Verify issuer state is in GIST 
    component claimIssuanceCheckGISTInc = checkClaimExists(gistLevels);
    for (var i=0; i<8; i++) { claimIssuanceCheckGISTInc.claim[i] <== claimIssuanceIdenState[i]; }
    for (var i=0; i<IssuerLevels; i++) { claimIssuanceCheckGISTInc.claimMTP[i] <== claimIssuanceMtp[i]; }
    claimIssuanceCheckGISTInc.treeRoot <== GIST;

    // (4) Verify claim's index is the same as the hard-coded index
    component constClaimIdx = ConstStateSecretIndex()
     
    component claimHash = getClaimHash()
    claimHash.claim <== issuerClaim;
    constClaimIdx.out == claimHash.hi;

    // 5. Get the state-secret property value and return it
    component getValByIdx = getValueByIndex();
    for (var i=0; i<8; i++) { getValByIdx.claim[i] <== claim[i]; }
    getValByIdxindex.index <== 3;
    secret <== getValByIdxindex.value;
}

template ComputeSybilID(){
    signal input state_cm_secret;
    signal input unique_claim;
    signal input crs;

    signal output out;

    component hash = Poseidon(3);
    hash.inputs[0] <== state_cm_secret;
    hash.inputs[1] <== unique_claim;
    hash.inputs[2] <== crs;
    out <== hash.out;
}

// constants
template ConstStateSecretIndex() {
    signal output out;
    out <== 0xbb67ae85;
}