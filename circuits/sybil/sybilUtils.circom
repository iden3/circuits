pragma circom 2.1.1;

template GetStateCommitmentPosition() {
    signal output out;
    out <== 11712158702391090353476752334536845532095615971587654091891297967623141028854;
}

template GetStateCommitmentSchemaHash(){
    signal output schemaHash;
    schemaHash <== 7082351036644153942426544930816155573;
}

template VerifyStateCommitment(UserLevels, GistLevels){ // stateCommitmentClaim
    signal input claim[8];
    signal input claimMtp[UserLevels];
    signal input claimClaimsRoot;
    signal input claimRevRoot;
    signal input claimRootsRoot;
    signal input claimIdenState;

    signal input gistMtp[GistLevels];
    signal input gistRoot;
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;

    signal input genesisID;

    // Verify claim is included in claims tree root
    component claimIssuanceCheck = checkClaimExists(UserLevels);
    for (var i=0; i<8; i++) { claimIssuanceCheck.claim[i] <== claim[i]; }
    for (var i=0; i<UserLevels; i++) { claimIssuanceCheck.claimMTP[i] <== claimMtp[i]; }
    claimIssuanceCheck.treeRoot <== claimClaimsRoot;
    claimIssuanceCheck.enabled <== 1;

    // Verify state includes claims tree
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.claimsTreeRoot <== claimClaimsRoot;
    verifyClaimIssuanceIdenState.revTreeRoot <== claimRevRoot;
    verifyClaimIssuanceIdenState.rootsTreeRoot <== claimRootsRoot;
    verifyClaimIssuanceIdenState.expectedState <== claimIdenState;
    verifyClaimIssuanceIdenState.enabled <== 1;

    component stateCommitmentSchemaHash = GetStateCommitmentSchemaHash();

    // Verify claim schema
    verifyCredentialSchema()(1, claim, stateCommitmentSchemaHash.schemaHash);

    component cutId = cutId();
    cutId.in <== genesisID;

    component cutState = cutState();
    cutState.in <== claimIdenState;

    component isStateGenesis = IsEqual();
    isStateGenesis.in[0] <== cutId.out;
    isStateGenesis.in[1] <== cutState.out;

    // Verify issuer state is in GIST 
    component genesisIDhash = Poseidon(1);
    genesisIDhash.inputs[0] <== genesisID;

    component gistCheck = SMTVerifier(GistLevels);
    gistCheck.enabled <== 1;
    gistCheck.fnc <== isStateGenesis.out; // non-inclusion in case if genesis state, otherwise inclusion
    gistCheck.root <== gistRoot;
    for (var i=0; i<GistLevels; i++) { gistCheck.siblings[i] <== gistMtp[i]; }
    gistCheck.oldKey <== gistMtpAuxHi;
    gistCheck.oldValue <== gistMtpAuxHv;
    gistCheck.isOld0 <== gistMtpNoAux;
    gistCheck.key <== genesisIDhash.out;
    gistCheck.value <== claimIdenState;

    // Verify claim's index is the same as the hard-coded index
    component constClaimIdx = GetStateCommitmentPosition();

    // Get the secret and return it
    component claimHash = getClaimHiHv();
    for (var i=0; i<8; i++) { claimHash.claim[i] <== claim[i]; }
    constClaimIdx.out === claimHash.hi;
}