pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "query.circom";
include "modifiers.circom";
include "../utils/claimUtils.circom";
include "../utils/arraySizeValidator.circom";

template ProcessQueryWithModifiers(claimLevels, maxValueArraySize){
    signal input enabled; 
    signal input claimPathNotExists; // 0 for inclusion, 1 for non-inclusion
    signal input claimPathMtp[claimLevels];
    signal input claimPathMtpNoAux; // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
    signal input claimPathMtpAuxHi; // 0 for inclusion proof
    signal input claimPathMtpAuxHv; // 0 for inclusion proof
    signal input claimPathKey; // hash of path in merklized json-ld document
    signal input claimPathValue; // value in this path in merklized json-ld document
    signal input slotIndex;
    signal input operator;
    signal input value[maxValueArraySize];
    signal input valueArraySize;

    signal input issuerClaim[8];
    signal input merklized;
    signal input merklizedRoot;

    // Modifier/Computation Operator output ($sd)
    signal output operatorOutput;

    signal smtEnabled <== AND()(enabled, merklized);

    // check path/in node exists in merkletree specified by jsonldRoot
    SMTVerifier(claimLevels)(
        enabled <== smtEnabled,  // if merklize flag 0 or enabled 0 skip MTP verification
        fnc <== claimPathNotExists, // inclusion
        root <== merklizedRoot,
        siblings <== claimPathMtp,
        oldKey <== claimPathMtpAuxHi,
        oldValue <== claimPathMtpAuxHv,
        isOld0 <== claimPathMtpNoAux,
        key <== claimPathKey,
        value <== claimPathValue
    ); // 9585 constraints

    // select value from claim by slot index (0-7)
    signal slotValue <== getValueByIndex()(issuerClaim, slotIndex);

    // select value for query verification,
    // if claim is merklized merklizeFlag = `1|2`, take claimPathValue
    // if not merklized merklizeFlag = `0`, take value from selected slot
    signal fieldValue <== Mux1()(
        [slotValue, claimPathValue],
        merklized
    );

    /////////////////////////////////////////////////////////////////
    // Query Operator Processing
    /////////////////////////////////////////////////////////////////

    // verify value array length
    // 802 constraints (ArraySizeValidator+ForceEqualIfEnabled)
    signal arrSizeSatisfied <== ArraySizeValidator(maxValueArraySize)(
        valueArraySize <== valueArraySize,
        operator <== operator
    );

    ForceEqualIfEnabled()(
        enabled,
        [arrSizeSatisfied, 1]
    );

    // verify query
    // 1756 constraints (Query+LessThan+ForceEqualIfEnabled)
    signal querySatisfied <== Query(maxValueArraySize)(
        in <== fieldValue,
        value <== value,
        valueArraySize <== valueArraySize,
        operator <== operator
    );

    signal isQueryOp <== LessThan(5)([operator, 16]);
    signal querySatisfiedEnabled <== AND()(enabled, isQueryOp);
    ForceEqualIfEnabled()(
        querySatisfiedEnabled,
        [querySatisfied, 1]
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
    operatorOutput <== modifierValidatorOutputSelector()(
        operator <== operator,
        modifierOutputs <== [
            fieldValue, // 16 - selective disclosure (16-16 = index 0)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 // 17-31 - not used
        ]
    );
}