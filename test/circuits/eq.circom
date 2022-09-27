pragma circom 2.0.0;

//include "../../circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

template EqWithLog(n) {
    signal input in[2];
    signal output out;

    log(in[0]);
    log(in[1]);

    component eq = IsEqual();
    eq.in[0] <== in[0];
    eq.in[1] <== in[1];
    out <== eq.out;
}

component main = EqWithLog(252);

