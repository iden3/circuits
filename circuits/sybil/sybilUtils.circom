pragma circom 2.0.0;

template GetStateSecretPosition() {
    signal output out;
    out <== 1974680877085411137074044236594333239180760340473446672920498187419060160560;
}

// A template to retrieve the hash of the state secret schema
template GetStateSecretSchemaHash(){
    signal output schemaHash;
    schemaHash <== 262057681346829900854325169563380898778;
}

template VerifyAndExtractValStateSecret(HolderLevel, GistLevels){
    signal input claim[8];
    signal input claimIssuanceMtp[HolderLevel];
    signal input claimIssuanceClaimsRoot;
    signal input claimIssuanceRevRoot;
    signal input claimIssuanceRootsRoot;
    signal input claimIssuanceIdenState;

    signal input gistMtp[GistLevels];
    signal input gistRoot;
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;

    signal input genesisID;

    signal output claimValueHash;

    // Verify claim is included in claims tree root
    component claimIssuanceCheck = checkClaimExists(HolderLevel);
    for (var i=0; i<8; i++) { claimIssuanceCheck.claim[i] <== claim[i]; }
    for (var i=0; i<HolderLevel; i++) { claimIssuanceCheck.claimMTP[i] <== claimIssuanceMtp[i]; }
    claimIssuanceCheck.treeRoot <== claimIssuanceClaimsRoot;

    // Verify state includes claims tree
    component verifyClaimIssuanceIdenState = checkIdenStateMatchesRoots();
    verifyClaimIssuanceIdenState.claimsTreeRoot <== claimIssuanceClaimsRoot;
    verifyClaimIssuanceIdenState.revTreeRoot <== claimIssuanceRevRoot;
    verifyClaimIssuanceIdenState.rootsTreeRoot <== claimIssuanceRootsRoot;
    verifyClaimIssuanceIdenState.expectedState <== claimIssuanceIdenState;

    component stateSecretSchemaHash = GetStateSecretSchemaHash();

    // Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== claim[i]; }
    claimSchemaCheck.schema <== stateSecretSchemaHash.schemaHash;

    component cutId = cutId();
    cutId.in <== genesisID;

    component cutState = cutState();
    cutState.in <== claimIssuanceIdenState;

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
    gistCheck.value <== claimIssuanceIdenState;

    // Verify claim's index is the same as the hard-coded index
    component constClaimIdx = GetStateSecretPosition();

    // Get the state-secret property value and return it
    component claimHash = getClaimHiHv();
    for (var i=0; i<8; i++) { claimHash.claim[i] <== claim[i]; }
    constClaimIdx.out === claimHash.hi;

    claimValueHash <== claimHash.hv;
}