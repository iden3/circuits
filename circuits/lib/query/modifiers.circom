pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/mux4.circom";

/*
    Modifier/computation operators:
      16 - selective disclosure (16 = 10000 binary)
      17 - nullify (17 = 10001 binary)
*/

// modifierValidatorOutputSelector validates modifier operation and selects output value
template modifierValidatorOutputSelector() {
    signal input operator;
    signal input modifierOutputs[16];
    signal output out;

    // parse operator to bits
    signal opBits[5] <== Num2Bits(5)(operator); // values 0-15 are query operators, 16-31 - modifiers/computations

    // modifier operation validation mux
    // it only validates that operator number is valid
    component modifierOpValid = Mux4();
    modifierOpValid.s <== [opBits[0], opBits[1], opBits[2], opBits[3]];
    modifierOpValid.c <== [
        1, // valid operator: 16 - selective disclosure (16-16 = index 0)
        1, // valid operator: 17 - nullify (17-16 = index 1)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    ForceEqualIfEnabled()(
        opBits[4], // equals to 1 for values 16-31
        [modifierOpValid.out, 1]
    );

    // output value calculation
    signal modifierOutput <== Mux4()(
        s <== [opBits[0], opBits[1], opBits[2], opBits[3]],
        c <== modifierOutputs
    );

    // output value only if modifier operation was selected
    out <== Mux1()(
        c <== [0, modifierOutput], // output 0 for non-modifier operations
        s <== opBits[4] // operator values 0-15 are query operators, 16-31 - modifiers/computations
    );
}
