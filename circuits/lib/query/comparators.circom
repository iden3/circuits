pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

// Checks if value `in` is included is in value array
// Returns 1 if at least one value is equal to `in`, 0 otherwise
// valueArraySize - size of value array
// Example: IN(3)(1, [12, 1231, 9999]) ==> 0 (1 is not in array of values)
// Example: IN(3)(1231, [12, 1231, 9999]) ==> 1 (1231 is in array of values)
template IN(valueArraySize){

        signal input in;
        signal input value[valueArraySize];
        signal output out;

        component eq[valueArraySize];
        signal isEq[valueArraySize+1];
        isEq[0] <== 0;
        for (var i=0; i<valueArraySize; i++) {
            eq[i] = IsEqual();
            eq[i].in[0] <== in;
            eq[i].in[1] <== value[i];
            isEq[i+1] <== OR()(isEq[i], eq[i].out);
        }

        out <== isEq[valueArraySize];
}

// Same as IN but stops checking on valueArraySize
// Example: InWithDynamicArraySize(5)(0, [12, 1231, 9999, 0, 0], 3) ==> 0 (0 is not in the first 3 elements of value array)
template InWithDynamicArraySize(maxValueArraySize){
        signal input in;
        signal input value[maxValueArraySize];
        signal input valueArraySize;
        signal output out;

        assert(maxValueArraySize <= 256);

        component eq[maxValueArraySize];
        signal isEq[maxValueArraySize+1];
        signal lt[maxValueArraySize];
        isEq[0] <== 0;
        for (var i=0; i<maxValueArraySize; i++) {
            lt[i] <== LessThan(9)([i, valueArraySize]);
            eq[i] = IsEqual();
            eq[i].in[0] <== in;
            eq[i].in[1] <== value[i];
            isEq[i+1] <== OR()(isEq[i], AND()(eq[i].out, lt[i]));
        }

        out <== isEq[maxValueArraySize];
}

// Checks if first number is less than second
// As LessThan but for all possible numbers from field (not only 252-bit-max like LessThan)
// Treats numbers as non-negative 254-bit numbers
template LessThan254() {
    signal input in[2];
    signal output out;

    component n0b = Num2Bits_strict();
    n0b.in <== in[0];

    component n1b = Num2Bits_strict();
    n1b.in <== in[1];

    // numbers for high 4 bits
    component h0  = Bits2Num(2);
    component h1  = Bits2Num(2);
    for(var i = 252; i < 254; i++) {
        h0.in[i-252] <== n0b.out[i];
        h1.in[i-252] <== n1b.out[i];
    }

    component hiBitLt = LessThan(2);
    hiBitLt.in[0] <== h0.out;
    hiBitLt.in[1] <== h1.out;
    component hiBitEq = IsEqual();
    hiBitEq.in[0] <== h0.out;
    hiBitEq.in[1] <== h1.out;

    // number for lower 252 bits
    component n0  = Bits2Num(252);
    component n1  = Bits2Num(252);
    for(var i = 0; i < 252; i++) {
        n0.in[i] <== n0b.out[i];
        n1.in[i] <== n1b.out[i];
    }

    component lt = LessThan(252);
    lt.in[0] <== n0.out;
    lt.in[1] <== n1.out;

    out <== (hiBitEq.out * lt.out) + (hiBitLt.out * 1);
}

template GreaterThan254() {
    signal input in[2];
    signal output out;

    component lt = LessThan254();

    lt.in[0] <== in[1];
    lt.in[1] <== in[0];
    lt.out ==> out;
}
