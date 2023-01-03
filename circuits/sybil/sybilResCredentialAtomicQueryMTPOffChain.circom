pragma circom 2.0.0;

include "sybilUtils.circom";
include "../lib/utils/idUtils.circom";
include "../lib/utils/treeUtils.circom";
include "../lib/utils/claimUtils.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";


template SybilResCredentialAtomicQueryMTPOffChain(IssuerLevels, HolderLevel, GistLevels) {

    // claim of uniqueness 
    signal input issuerClaim[8];
    signal input issuerClaimMtp[IssuerLevels];
    signal input issuerClaimClaimsRoot;
    signal input issuerClaimRevRoot;
    signal input issuerClaimRootsRoot;
    signal input issuerClaimIdenState;

    signal input issuerClaimNonRevMtp[IssuerLevels];
    signal input issuerClaimNonRevMtpNoAux;
    signal input issuerClaimNonRevMtpAuxHi;
    signal input issuerClaimNonRevMtpAuxHv;

    signal input issuerClaimNonRevClaimsRoot;
    signal input issuerClaimNonRevRevRoot;
    signal input issuerClaimNonRevRootsRoot;
    signal input issuerClaimNonRevState;

    signal input issuerClaimSchema;

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
    signal input timestamp;

    // inter-signal
    signal issuerClaimHash;
    signal holderClaimValueHash;

    // outputs
    signal output userID;
    signal output sybilID;

    component verifyUniClaim = VerifyAndHashUniClaim(IssuerLevels);
    for (var i=0; i<8; i++) { verifyUniClaim.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyUniClaim.claimMtp[i] <== issuerClaimMtp[i]; }
    verifyUniClaim.claimClaimsRoot  <== issuerClaimClaimsRoot;
    verifyUniClaim.claimRevRoot  <== issuerClaimRevRoot;
    verifyUniClaim.claimRootsRoot  <== issuerClaimRootsRoot;
    verifyUniClaim.claimIdenState  <== issuerClaimIdenState;

    for (var i=0; i<IssuerLevels; i++) { verifyUniClaim.claimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    verifyUniClaim.claimNonRevMtpNoAux  <== issuerClaimNonRevMtpNoAux;
    verifyUniClaim.claimNonRevMtpAuxHi  <== issuerClaimNonRevMtpAuxHi;
    verifyUniClaim.claimNonRevMtpAuxHv  <== issuerClaimNonRevMtpAuxHv;
    verifyUniClaim.claimNonRevClaimsRoot  <== issuerClaimNonRevClaimsRoot;
    verifyUniClaim.claimNonRevRevRoot  <== issuerClaimNonRevRevRoot;
    verifyUniClaim.claimNonRevRootsRoot  <== issuerClaimNonRevRootsRoot;
    verifyUniClaim.claimNonRevState  <== issuerClaimNonRevState;

    verifyUniClaim.claimSchema  <== issuerClaimSchema;

    verifyUniClaim.userGenesisID  <== userGenesisID;
    verifyUniClaim.profileNonce <== profileNonce;
    verifyUniClaim.claimSubjectProfileNonce <== claimSubjectProfileNonce;
    verifyUniClaim.timestamp <== timestamp;

    verifyUniClaim.claimHash  ==> issuerClaimHash;

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

    // Compute UserId
    component selectProfile = SelectProfile();
    selectProfile.in <== userGenesisID;
    selectProfile.nonce <== profileNonce;
    userID <== selectProfile.out;
}


template VerifyAndHashUniClaim(IssuerLevels){
    signal input claim[8];
    signal input claimMtp[IssuerLevels];
    signal input claimClaimsRoot;
    signal input claimRevRoot;
    signal input claimRootsRoot;
    signal input claimIdenState;

    signal input claimNonRevMtp[IssuerLevels];
    signal input claimNonRevMtpNoAux;
    signal input claimNonRevMtpAuxHi;
    signal input claimNonRevMtpAuxHv;
    signal input claimNonRevClaimsRoot;
    signal input claimNonRevRevRoot;
    signal input claimNonRevRootsRoot;
    signal input claimNonRevState;

    signal input claimSchema;

    signal input timestamp;

    signal input userGenesisID;
    signal input profileNonce;
    signal input claimSubjectProfileNonce;

    signal output claimHash;

    // Verify claim issued
    component vci = verifyClaimIssuanceNonRev(IssuerLevels);
    for (var i=0; i<8; i++) { vci.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) { vci.claimIssuanceMtp[i] <== claimMtp[i]; }
    vci.claimIssuanceClaimsTreeRoot <== claimClaimsRoot;
    vci.claimIssuanceRevTreeRoot <== claimRevRoot;
    vci.claimIssuanceRootsTreeRoot <== claimRootsRoot;
    vci.claimIssuanceIdenState <== claimIdenState;
    vci.enabledNonRevCheck <== 1;

    // And non revocation status
    for (var i=0; i<IssuerLevels; i++) { vci.claimNonRevMtp[i] <== claimNonRevMtp[i]; }
    vci.claimNonRevMtpNoAux <== claimNonRevMtpNoAux;
    vci.claimNonRevMtpAuxHi <== claimNonRevMtpAuxHi;
    vci.claimNonRevMtpAuxHv <== claimNonRevMtpAuxHv;
    vci.claimNonRevIssuerClaimsTreeRoot <== claimNonRevClaimsRoot;
    vci.claimNonRevIssuerRevTreeRoot <== claimNonRevRevRoot;
    vci.claimNonRevIssuerRootsTreeRoot <== claimNonRevRootsRoot;
    vci.claimNonRevIssuerState <== claimNonRevState;

    // Verify issuerClaim expiration time
    component claimExpirationCheck = verifyExpirationTime();
    for (var i=0; i<8; i++) { claimExpirationCheck.claim[i] <== claim[i]; }
    claimExpirationCheck.timestamp <== timestamp;

    // Verify claim schema
    component claimSchemaCheck = verifyCredentialSchema();
    for (var i=0; i<8; i++) { claimSchemaCheck.claim[i] <== claim[i]; }
    claimSchemaCheck.schema <== claimSchema;

    // Check claim is issued to provided identity
    component claimIdCheck = verifyCredentialSubjectProfile();
    for (var i=0; i<8; i++) { claimIdCheck.claim[i] <== claim[i]; }
    claimIdCheck.id <== userGenesisID;
    claimIdCheck.nonce <== claimSubjectProfileNonce;

    // Get claim hash
    component hasher = getClaimHash();
    for (var i=0; i<8; i++) { hasher.claim[i] <== claim[i]; }
    claimHash <== hasher.hash;
}



