pragma circom 2.0.0;

//include "../../circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

template LessThanWithLog(n) {
    signal input in[2];
    signal output out;

    log(in[0]);
    log(in[1]);

    component lt = LessThan(n);
    lt.in[0] <== in[0];
    lt.in[1] <== in[1];
    out <== lt.out;
}

component main = LessThanWithLog(252);

