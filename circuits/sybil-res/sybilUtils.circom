
template ComputeSybilID(){
    signal input stateSecret;
    signal input claimHash;
    signal input crs;

    signal output out;

    component hash = Poseidon(3);
    hash.inputs[0] <== stateSecret;
    hash.inputs[1] <== claimHash;
    hash.inputs[2] <== crs;
    out <== hash.out;
}

// constants
template ConstStateSecretIndex() {
    signal output out;
    out <== 0xbb67ae85;
}


template VerifyAndExtractValStateSecret(holderLevels, gistLevels){
    signal input claim[8];
    signal input claimIssuanceMtp[holderLevels];
    signal input claimIssuanceClaimsRoot;
    signal input claimIssuanceRevRoot;
    signal input claimIssuanceRootsRoot;
    signal input claimIssuanceIdenState;

    signal input claimSchema;

    signal input idenGistMtp[gistLevels];
    signal input idenGistState[8];              // double check this declration 
    signal input gist;

    signal output secret;
    // (1) Verify claim is included in claims tree root
    component claimIssuanceCheck = checkClaimExists(holderLevels);
    for (var i=0; i<8; i++) { claimIssuanceCheck.claim[i] <== claim[i]; }
    for (var i=0; i<holderLevels; i++) { claimIssuanceCheck.claimMTP[i] <== claimIssuanceMtp[i]; }
    claimIssuanceCheck.treeRoot <== claimIssuanceClaimsRoot;

    // verify state includes claims tree
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.claimsTreeRoot <== claimIssuanceClaimsRoot;
    verifyClaimIssuanceIdenState.revTreeRoot <== claimIssuanceRevRoot;
    verifyClaimIssuanceIdenState.rootsTreeRoot <== claimIssuanceRootsRoot;
    verifyClaimIssuanceIdenState.expectedState <== claimIssuanceIdenState;

    // (2) Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== claim[i]; }
    claimSchemaCheck.schema <== claimSchema;

    // (3) Verify issuer state is in GIST 
    component claimIssuanceCheckGISTInc = checkClaimExists(gistLevels);
    for (var i=0; i<8; i++) { claimIssuanceCheckGISTInc.claim[i] <== idenGistState[i]; }
    for (var i=0; i<gistLevels; i++) { claimIssuanceCheckGISTInc.claimMTP[i] <== idenGistMtp[i]; }
    claimIssuanceCheckGISTInc.treeRoot <== gist;

    // (4) Verify claim's index is the same as the hard-coded index
    component constClaimIdx = ConstStateSecretIndex()
     
    component claimHash = getClaimHash()
    for (var i=0; i<8; i++) { claimHash.claim[i] <== claim[i]; }
    constClaimIdx.out == claimHash.hi;

    // 5. Get the state-secret property value and return it
    component getValByIdx = getValueByIndex();
    for (var i=0; i<8; i++) { getValByIdx.claim[i] <== claim[i]; }
    getValByIdxindex.index <== 2;           // pre-defined in the protocol protcol 
    secret <== getValByIdxindex.value;
}