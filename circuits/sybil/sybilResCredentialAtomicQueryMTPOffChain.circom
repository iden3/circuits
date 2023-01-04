pragma circom 2.0.0;

include "sybilUtils.circom";
include "../lib/utils/idUtils.circom";
include "../lib/utils/treeUtils.circom";
include "../lib/utils/claimUtils.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";


template SybilResCredentialAtomicQueryMTPOffChain(IssuerLevels, HolderLevel, GistLevels) {

    // uniqueness claim
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

    // state commitment claim
    signal input stateCommitmentClaim[8];
    signal input stateCommitmentClaimMtp[HolderLevel];
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

    // inter-signal
    signal issuerClaimHash;
    signal stateCommitmentClaimValueHash;

    // outputs
    signal output userID;
    signal output sybilID;

    component verifyIssuerClaim = VerifyAndHashIssuerClaim(IssuerLevels);
    for (var i=0; i<8; i++) { verifyIssuerClaim.claim[i] <== issuerClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyIssuerClaim.claimMtp[i] <== issuerClaimMtp[i]; }
    verifyIssuerClaim.claimClaimsRoot  <== issuerClaimClaimsRoot;
    verifyIssuerClaim.claimRevRoot  <== issuerClaimRevRoot;
    verifyIssuerClaim.claimRootsRoot  <== issuerClaimRootsRoot;
    verifyIssuerClaim.claimIdenState  <== issuerClaimIdenState;

    for (var i=0; i<IssuerLevels; i++) { verifyIssuerClaim.claimNonRevMtp[i] <== issuerClaimNonRevMtp[i]; }
    verifyIssuerClaim.claimNonRevMtpNoAux  <== issuerClaimNonRevMtpNoAux;
    verifyIssuerClaim.claimNonRevMtpAuxHi  <== issuerClaimNonRevMtpAuxHi;
    verifyIssuerClaim.claimNonRevMtpAuxHv  <== issuerClaimNonRevMtpAuxHv;
    verifyIssuerClaim.claimNonRevClaimsRoot  <== issuerClaimNonRevClaimsRoot;
    verifyIssuerClaim.claimNonRevRevRoot  <== issuerClaimNonRevRevRoot;
    verifyIssuerClaim.claimNonRevRootsRoot  <== issuerClaimNonRevRootsRoot;
    verifyIssuerClaim.claimNonRevState  <== issuerClaimNonRevState;

    verifyIssuerClaim.claimSchema  <== issuerClaimSchema;

    verifyIssuerClaim.userGenesisID  <== userGenesisID;
    verifyIssuerClaim.profileNonce <== profileNonce;
    verifyIssuerClaim.claimSubjectProfileNonce <== claimSubjectProfileNonce;
    verifyIssuerClaim.timestamp <== timestamp;

    verifyIssuerClaim.claimHash  ==> issuerClaimHash;

    component verifyStateCommitment = VerifyAndExtractValStateCommitment(HolderLevel, GistLevels);
    for (var i=0; i<8; i++) { verifyStateCommitment.claim[i] <== stateCommitmentClaim[i]; }
    for (var i=0; i<HolderLevel; i++) { verifyStateCommitment.claimMtp[i] <== stateCommitmentClaimMtp[i]; }
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

    verifyStateCommitment.claimValueHash ==> stateCommitmentClaimValueHash;
    
    // Compute SybilId
    component hash = Poseidon(3);
    hash.inputs[0] <== stateCommitmentClaimValueHash;
    hash.inputs[1] <== issuerClaimHash;
    hash.inputs[2] <== crs;
    sybilID <== hash.out;

    // Compute UserId
    component selectProfile = SelectProfile();
    selectProfile.in <== userGenesisID;
    selectProfile.nonce <== profileNonce;
    userID <== selectProfile.out;
}


template VerifyAndHashIssuerClaim(IssuerLevels){
    signal input claim[8];
    signal input claimMtp[IssuerLevels];
    signal input claimClaimsRoot;
    signal input claimRevRoot;
    signal input claimRootsRoot;
    signal input claimIdenState;

    signal input claimSchema;

    signal input claimNonRevMtp[IssuerLevels];
    signal input claimNonRevMtpNoAux;
    signal input claimNonRevMtpAuxHi;
    signal input claimNonRevMtpAuxHv;
    signal input claimNonRevClaimsRoot;
    signal input claimNonRevRevRoot;
    signal input claimNonRevRootsRoot;
    signal input claimNonRevState;

    signal input timestamp;

    signal input userGenesisID;
    signal input profileNonce;
    signal input claimSubjectProfileNonce;

    signal output claimHash;

    // Verify claim issued
    component vci = verifyClaimIssuanceNonRev(IssuerLevels);
    vci.enabledNonRevCheck <== 1;
    for (var i=0; i<8; i++) { vci.claim[i] <== claim[i]; }
    for (var i=0; i<IssuerLevels; i++) { vci.claimIssuanceMtp[i] <== claimMtp[i]; }
    vci.claimIssuanceClaimsTreeRoot <== claimClaimsRoot;
    vci.claimIssuanceRevTreeRoot <== claimRevRoot;
    vci.claimIssuanceRootsTreeRoot <== claimRootsRoot;
    vci.claimIssuanceIdenState <== claimIdenState;

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


