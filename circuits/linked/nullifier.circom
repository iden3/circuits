pragma circom 2.1.5;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/linked/linkId.circom";
include "../lib/query/nullify.circom";
include "../lib/utils/safeOne.circom";
include "../lib/utils/claimUtils.circom";

// This circuit generates nullifier for a given claim using linked proof
template LinkedNullifier(){

    // linked proof signals
    signal input linkID;
    signal input linkNonce;
    signal input issuerClaim[8];

    // nullifier signals
    signal input userGenesisID;
    signal input claimSubjectProfileNonce;
    signal input claimSchema;
    signal input verifierID;
    signal input verifierSessionID;

    signal output nullifier;

    // get safe one values to be used in ForceEqualIfEnabled
    signal one <== SafeOne()(userGenesisID); // 7 constraints

    ////////////////////////////////////////////////////////////////////////
    // verify nullifier signals
    ////////////////////////////////////////////////////////////////////////

    component issuerClaimHeader = getClaimHeader(); // 300 constraints
    issuerClaimHeader.claim <== issuerClaim;

    // Verify issuerClaim schema
    verifyCredentialSchema()(one, issuerClaimHeader.schema, claimSchema); // 3 constraints

    // Check issuerClaim is issued to provided identity
    verifyCredentialSubjectProfile()(
        one,
        issuerClaim,
        issuerClaimHeader.claimFlags,
        userGenesisID,
        claimSubjectProfileNonce
    ); // 1236 constraints

    signal issuerClaimHash, issuerClaimHi, issuerClaimHv;
    (issuerClaimHash, issuerClaimHi, issuerClaimHv) <== getClaimHash()(issuerClaim); // 834 constraints

    ////////////////////////////////////////////////////////////////////////
    // verify linkID
    ////////////////////////////////////////////////////////////////////////
    signal calculatedLinkID <== LinkID()(issuerClaimHash, linkNonce); // 243 constraints
    ForceEqualIfEnabled()(one, [calculatedLinkID, linkID]);

    signal linkIDisNotZero <== NOT()(IsZero()(linkID));
    ForceEqualIfEnabled()(one, [linkIDisNotZero, one]);

    ////////////////////////////////////////////////////////////////////////
    // calculate nullifier
    ////////////////////////////////////////////////////////////////////////
    nullifier <== Nullify()(
        userGenesisID,
        claimSubjectProfileNonce,
        claimSchema,
        verifierID,
        verifierSessionID
    ); // 330 constraints

}