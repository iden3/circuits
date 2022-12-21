
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
template GetStateSecretIndex() {
    signal output out;
    out <== 3;
}

template GetStateSecretSlot() {
    signal output out;
    out <== 3;
}

template GetStateSecretSchemaHash(){
    signal output schemaHash;
    schemaHash <== 301485908906857522017021291028488077057;
}


template VerifyAndExtractValStateSecret(holderLevels, gistLevels){
    signal input claim[8];
    signal input claimIssuanceMtp[holderLevels];
    signal input claimIssuanceClaimsRoot;
    signal input claimIssuanceRevRoot;
    signal input claimIssuanceRootsRoot;
    signal input claimIssuanceIdenState; // aka idenGistState

    // signal input claimSchema;

    signal input gistMtp[gistLevels];
    // signal input idenGistState;              // double check this declration 
    signal input gistRoot;
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;

    signal input userId;

    // inter
    signal expectedClaimIdx;
    signal stateSecretSchema;

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

    component stateSecretSchemaHash = GetStateSecretSchemaHash();
    stateSecretSchema <== stateSecretSchema.schemaHash;

    // (2) Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== claim[i]; }
    claimSchemaCheck.schema <== stateSecretSchema;

    // (3) Verify issuer state is in GIST 
    component genesisIDhash = Poseidon(1);
    genesisIDhash.inputs[0] <== userId;

    component gistCheck = SMTVerifier(gistLevels);
    gistCheck.enabled <== 1;
    gistCheck.fnc <== 0; // non-inclusion in case if genesis state, otherwise inclusion
    gistCheck.root <== gistRoot;
    for (var i=0; i<gistLevels; i++) { gistCheck.siblings[i] <== gistMtp[i]; }
    gistCheck.oldKey <== gistMtpAuxHi;
    gistCheck.oldValue <== gistMtpAuxHv;
    gistCheck.isOld0 <== gistMtpNoAux;
    gistCheck.key <== genesisIDhash.out;
    gistCheck.value <== claimIssuanceIdenState;

    // (4) Verify claim's index is the same as the hard-coded index
    component constClaimIdx = GetStateSecretIndex();
    expectedClaimIdx <== constClaimIdx.out;

    component claimHash = getClaimHash();
    for (var i=0; i<8; i++) { claimHash.claim[i] <== claim[i]; }
    expectedClaimIdx == claimHash.hi;

    component protocolClaimSlot = GetStateSecretSlot();
    protocolClaimSlotIdx <== protocolClaimSlot.out;

    // 5. Get the state-secret property value and return it
    component getValByIdx = getValueByIndex();
    for (var i=0; i<8; i++) { getValByIdx.claim[i] <== claim[i]; }
    getValByIdx.index <== protocolClaimSlotIdx;           // pre-defined in the protcol 
    secret <== getValByIdx.value;
}