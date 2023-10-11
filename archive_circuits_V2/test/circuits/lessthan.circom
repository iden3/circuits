pragma circom 2.1.1;

include "../../circuits/lib/query/comparators.circom";
//include "../../node_modules/circomlib/circuits/comparators.circom";

template LessThanWithLog() {
    signal input in[2];
    signal output out;

    log(in[0]);
    log(in[1]);

    component lt = LessThan254();
    lt.in[0] <== in[0];
    lt.in[1] <== in[1];
    out <== lt.out;
}

component main = LessThanWithLog();

