pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "comparators.circom";

/*
  Operators:
 "0" - equals
 "1" - less-than
 "2" - greater-than
 "3" - in
 "4" - notin
*/
template Query (valueArraySize) {
    // signals
    signal input in;
    signal input value[valueArraySize];
    signal input operator;
    signal output out;

    // operation components
    component eq = IsEqual();
    eq.in[0] <== in;
    eq.in[1] <== value[0];

    // LessThan
    component lt = LessThan(252);
    lt.in[0] <== in;
    lt.in[1] <== value[0];

    component gt = GreaterThan(252);
    gt.in[0] <== in;
    gt.in[1] <== value[0];

    // in
    component inComp = IN(valueArraySize);
    inComp.in <== in;
    for(var i = 0; i<valueArraySize; i++){inComp.value[i] <== value[i];}

    // mux
    component mux = Mux3();
    component n2b = Num2Bits(3);
    n2b.in <== operator;

    mux.s[0] <== n2b.out[0];
    mux.s[1] <== n2b.out[1];
    mux.s[2] <== n2b.out[2];

    mux.c[0] <== eq.out;
    mux.c[1] <== lt.out;
    mux.c[2] <== gt.out;
    mux.c[3] <== inComp.out;

    mux.c[4] <== 1-inComp.out;

    mux.c[5] <== 0; // not in use
    mux.c[6] <== 0; // not in use
    mux.c[7] <== 0; // not in use

    // output
    out <== mux.out;
}


