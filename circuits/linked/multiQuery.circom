pragma circom 2.1.5;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/linked/linkId.circom";
include "../lib/query/query.circom";
include "../lib/query/modifiers.circom";
include "../lib/utils/safeOne.circom";
include "../lib/utils/claimUtils.circom";

// This circuit generates nullifier for a given claim using linked proof
template LinkedMultiQuery(N, claimLevels, valueArraySize) {

    // linked proof signals
    signal input linkID;
    signal input linkNonce;
    signal input issuerClaim[8];

    // query signals
    // TODO: add enabled flag for each query
    // TODO: add query hash
    signal input claimPathNotExists[N]; // 0 for inclusion, 1 for non-inclusion
    signal input claimPathMtp[N][claimLevels];
    signal input claimPathMtpNoAux[N]; // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
    signal input claimPathMtpAuxHi[N]; // 0 for inclusion proof
    signal input claimPathMtpAuxHv[N]; // 0 for inclusion proof
    signal input claimPathKey[N]; // hash of path in merklized json-ld document
    signal input claimPathValue[N]; // value in this path in merklized json-ld document

    signal input slotIndex[N];
    signal input operator[N];
    signal input value[N][valueArraySize];

    // Modifier/Computation Operator output ($sd)
    signal output operatorOutput[N];
    signal output merklized;

    // get safe one values to be used in ForceEqualIfEnabled
    signal one <== SafeOne()(linkID); // 7 constraints

    component issuerClaimHeader = getClaimHeader(); // 300 constraints
    issuerClaimHeader.claim <== issuerClaim;

    component merklize = getClaimMerklizeRoot();
    merklize.claim <== issuerClaim;
    merklize.claimFlags <== issuerClaimHeader.claimFlags;

    merklized <== merklize.flag;

    signal slotValue[N];
    signal fieldValue[N];
    signal querySatisfied[N];
    signal isQueryOp[N];

    for (var i=0; i<N; i++) {

        /////////////////////////////////////////////////////////////////
        // Field Path and Value Verification
        /////////////////////////////////////////////////////////////////

        // check path/in node exists in merkletree specified by jsonldRoot
        SMTVerifier(claimLevels)(
            enabled <== merklize.flag,  // if merklize flag 0 skip MTP verification
            fnc <== claimPathNotExists[i], // inclusion
            root <== merklize.out,
            siblings <== claimPathMtp[i],
            oldKey <== claimPathMtpAuxHi[i],
            oldValue <== claimPathMtpAuxHv[i],
            isOld0 <== claimPathMtpNoAux[i],
            key <== claimPathKey[i],
            value <== claimPathValue[i]
        ); // 9585 constraints

        // select value from claim by slot index (0-7)
        slotValue[i] <== getValueByIndex()(issuerClaim, slotIndex[i]);

        // select value for query verification,
        // if claim is merklized merklizeFlag = `1|2`, take claimPathValue
        // if not merklized merklizeFlag = `0`, take value from selected slot
        fieldValue[i] <== Mux1()(
            [slotValue[i], claimPathValue[i]],
            merklize.flag
        );

        /////////////////////////////////////////////////////////////////
        // Query Operator Processing
        /////////////////////////////////////////////////////////////////

        // verify query
        // 1756 constraints (Query+LessThan+ForceEqualIfEnabled)
        querySatisfied[i] <== Query(valueArraySize)(
            in <== fieldValue[i],
            value <== value[i],
            operator <== operator[i]
        );

        isQueryOp[i] <== LessThan(5)([operator[i], 16]);
        ForceEqualIfEnabled()(
            isQueryOp[i],
            [querySatisfied[i], 1]
        );

        /////////////////////////////////////////////////////////////////
        // Modifier/Computation Operators Processing
        /////////////////////////////////////////////////////////////////

        // selective disclosure
        // no need to calc anything, fieldValue is just passed as an output

        /////////////////////////////////////////////////////////////////
        // Modifier Operator Validation & Output Preparation
        /////////////////////////////////////////////////////////////////

        // output value only if modifier operation was selected
        operatorOutput[i] <== modifierValidatorOutputSelector()(
            operator <== operator[i],
            modifierOutputs <== [
                fieldValue[i], // 16 - selective disclosure (16-16 = index 0)
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 // 17-31 - not used
            ]
        );
    }
}