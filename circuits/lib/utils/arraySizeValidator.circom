pragma circom 2.1.1;
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/mux4.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../query/comparators.circom";
/*
  Operators:
    Query operators - valueArraySize
      0 - noop - 0 elements
      1 - equals - 1 element
      2 - less than - 1 element
      3 - greater than - 1 element
      4 - in - less or eq than maxValueArraySize
      5 - not in - less or eq than maxValueArraySize
      6 - not equals - 1 element
      7 - less than or equal - 1 element 
      8 - greater than or equal - 1 element
      9 - between - 2 elements
    Modifier/computation operators:
      16 - selective disclosure (16 = 10000 binary) - 0 elements
      17-31 - 0 elements
*/

// ArraySizeValidator template check valueArraySize for query operators
template ArraySizeValidator (maxValueArraySize) {
    // signals
    signal input valueArraySize;
    signal input operator;
    signal output out;

    signal sizeEqZero <== IsEqual()([valueArraySize, 0]);
    signal sizeEqOne <== IsEqual()([valueArraySize, 1]);
    signal sizeEqTwo <== IsEqual()([valueArraySize, 2]);
    signal sizeLessOrEqMax <== LessThan254()([valueArraySize, maxValueArraySize + 1]);

    signal opBits[5] <== Num2Bits(5)(operator); // values 0-15 are query operators, 16-31 - modifiers/computations

    // query operator mux
    component mux = Mux4();
    mux.s <== [opBits[0], opBits[1], opBits[2], opBits[3]];

    // We don't use 5th bit (opBits[4]) here; which specifies whether operator is query or
    // modifier/computation operator. It's used in the final mux.
    _ <== opBits[4];

    mux.c[0] <== sizeEqZero; // noop; skip execution
    mux.c[1] <== sizeEqOne; // equals
    mux.c[2] <== sizeEqOne; // lt
    mux.c[3] <== sizeEqOne; // gt
    mux.c[4] <== sizeLessOrEqMax; // in
    mux.c[5] <== sizeLessOrEqMax; // nin
    mux.c[6] <== sizeEqOne; // neq
    mux.c[7] <== sizeEqOne; // lte
    mux.c[8] <== sizeEqOne; // gte
    mux.c[9] <== sizeEqTwo; // between
    mux.c[10] <== sizeEqZero; // not used
    mux.c[11] <== sizeEqZero; // not used
    mux.c[12] <== sizeEqZero; // not used
    mux.c[13] <== sizeEqZero; // not used
    mux.c[14] <== sizeEqZero; // not used
    mux.c[15] <== sizeEqZero; // not used
    
    // final output mux
    out <== Mux1()(
        s <== opBits[4], // specifies whether operator is query or modifier/computation operator
        c <== [mux.out, sizeEqZero]
    );
    
}


