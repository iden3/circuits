pragma circom 2.1.5;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/query/processQueryWithModifiers.circom";
include "../lib/linked/linkId.circom";
include "../lib/utils/claimUtils.circom";
include "../lib/utils/safeOne.circom";
include "../lib/utils/spongeHash.circom";

// This circuit processes multiple query requests at once for a given claim using linked proof
template LinkedMultiQuery(N, claimLevels, maxValueArraySize) {

    // linked proof signals
    signal input linkNonce;
    signal input issuerClaim[8];

    // query signals
    signal input enabled[N]; // 1 if query non-empty, 0 to skip query check
    signal input claimSchema;
    signal input claimPathNotExists[N]; // 0 for inclusion, 1 for non-inclusion
    signal input claimPathMtp[N][claimLevels];
    signal input claimPathMtpNoAux[N]; // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
    signal input claimPathMtpAuxHi[N]; // 0 for inclusion proof
    signal input claimPathMtpAuxHv[N]; // 0 for inclusion proof
    signal input claimPathKey[N]; // hash of path in merklized json-ld document
    signal input claimPathValue[N]; // value in this path in merklized json-ld document
    signal input slotIndex[N];
    signal input operator[N];
    signal input value[N][maxValueArraySize];
    signal input valueArraySize[N];


    // Outputs
    signal output linkID;
    signal output merklized;
    signal output operatorOutput[N];
    signal output circuitQueryHash[N];

    /////////////////////////////////////////////////////////////////
    // General verifications
    /////////////////////////////////////////////////////////////////

    // get safe one values to be used in ForceEqualIfEnabled
    signal one <== SafeOne()(linkNonce); // 7 constraints

    // get claim header
    component issuerClaimHeader = getClaimHeader(); // 300 constraints
    issuerClaimHeader.claim <== issuerClaim;

    // get merklized flag & root
    component merklize = getClaimMerklizeRoot();
    merklize.claim <== issuerClaim;
    merklize.claimFlags <== issuerClaimHeader.claimFlags;

    merklized <== merklize.flag;

    // Verify issuerClaim schema
    verifyCredentialSchema()(one, issuerClaimHeader.schema, claimSchema); // 3 constraints

    signal valueHash[N];
    signal queryHash[N];

    signal issuerClaimHash, issuerClaimHi, issuerClaimHv;
    (issuerClaimHash, issuerClaimHi, issuerClaimHv) <== getClaimHash()(issuerClaim); // 834 constraints
    ////////////////////////////////////////////////////////////////////////
    // calculate linkID
    ////////////////////////////////////////////////////////////////////////
    linkID <== LinkID()(issuerClaimHash, linkNonce); // 243 constraints

    /////////////////////////////////////////////////////////////////
    // Query Processing Loop
    /////////////////////////////////////////////////////////////////
    for (var i=0; i<N; i++) {

        // output value only if modifier operation was selected
        operatorOutput[i] <== ProcessQueryWithModifiers(claimLevels, maxValueArraySize)(
            enabled[i],
            claimPathNotExists[i],
            claimPathMtp[i],
            claimPathMtpNoAux[i],
            claimPathMtpAuxHi[i],
            claimPathMtpAuxHv[i],
            claimPathKey[i],
            claimPathValue[i],
            slotIndex[i],
            operator[i],
            value[i],
            valueArraySize[i],
            issuerClaim,
            merklized,
            merklize.out
        );

        /////////////////////////////////////////////////////////////////
        // Calculate query hash
        /////////////////////////////////////////////////////////////////
        // 4950 constraints (SpongeHash+Poseidon)
        valueHash[i] <== SpongeHash(maxValueArraySize, 6)(value[i]); // 6 - max size of poseidon hash available on-chain
        queryHash[i] <== Poseidon(6)([
            claimSchema,
            slotIndex[i],
            operator[i],
            claimPathKey[i],
            claimPathNotExists[i],
            valueHash[i]
        ]);

        circuitQueryHash[i] <== Mux1()([0, queryHash[i]], enabled[i]);
    }
}