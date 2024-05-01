pragma circom 2.1.1;
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/mux4.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "comparators.circom";

/*
  Operators:
    Query operators:
      0 - noop. Ignores all `in` and `value` passed to query, out 1
      1 - equals
      2 - less than
      3 - greater than
      4 - in
      5 - not in
      6 - not equals
      7 - less than or equal
      8 - greater than or equal
      9 - between (value[0] <= in <= value[1])
      10 - not between
      11 - exists (true / false)
    Modifier/computation operators:
      16 - selective disclosure (16 = 10000 binary)
      17 - value commitment (17 = 10001 binary)
*/

// Query template works only with Query operators (0-15).
// Returns 1 if query operator is satisfied, 0 otherwise.
// For modifier/computation operators (16-31) it always returns 0.
template Query (maxValueArraySize) {
    // signals
    signal input in;
    signal input value[maxValueArraySize];
    signal input valueArraySize;
    signal input operator;
    signal output out;

    // Equals
    signal eq <== IsEqual()([in, value[0]]);

    // LessThan
    signal lt <== LessThan254()([in, value[0]]); // 767 constraints

    // lte
    signal lte <== OR()(lt, eq); // lte === lt || eq

    // GreaterThan
    signal gt <== NOT()(lte); // gt === !lte

    // gte
    signal gte <== NOT()(lt); // gte === !lt

    // in           w/o - 65668, IN - 65860( 192), InWithDynamicArraySize - 66372 (704)
    signal inComp <== InWithDynamicArraySize(maxValueArraySize)(in, value, valueArraySize);

    // between (value[0] <= in <= value[1])
    signal gt2 <== GreaterThan254()([in, value[1]]);
    signal lte2 <== NOT()(gt2); // lte === !gt
    signal between <== AND()(gte, lte2);

    signal opBits[5] <== Num2Bits(5)(operator); // values 0-15 are query operators, 16-31 - modifiers/computations

    // query operator mux
    component queryOpSatisfied = Mux4();
    queryOpSatisfied.s <== [opBits[0], opBits[1], opBits[2], opBits[3]];
    // We don't use 5th bit (opBits[4]) here; which specifies whether operator is query or
    // modifier/computation operator. It's used in the final mux.
    _ <== opBits[4];

    queryOpSatisfied.c[0] <== 1; // noop; always succeeds
    queryOpSatisfied.c[1] <== eq;
    queryOpSatisfied.c[2] <== lt;
    queryOpSatisfied.c[3] <== gt;
    queryOpSatisfied.c[4] <== inComp; // in
    queryOpSatisfied.c[5] <== NOT()(inComp); // nin
    queryOpSatisfied.c[6] <== NOT()(eq); // neq
    queryOpSatisfied.c[7] <== lte; // lte === !gt
    queryOpSatisfied.c[8] <== gte; // gte === !lt
    queryOpSatisfied.c[9] <== between; // between
    queryOpSatisfied.c[10] <== NOT()(between); // not between
    queryOpSatisfied.c[11] <== 1; // exists(true/false) - actual check is done by checking inclusion/non-inclusion of claimPathKey in merklized root by SMTVerifier outside
    queryOpSatisfied.c[12] <== 0; // not used
    queryOpSatisfied.c[13] <== 0; // not used
    queryOpSatisfied.c[14] <== 0; // not used
    queryOpSatisfied.c[15] <== 0; // not used

    // final output mux
    out <== Mux1()(
        s <== opBits[4], // specifies whether operator is query or modifier/computation operator
        c <== [queryOpSatisfied.out, 0]
    );
}


