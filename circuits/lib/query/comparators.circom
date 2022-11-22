pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/comparators.circom";

// nElements - number of value elements
// Example nElements = 3, '1' v ['12', '1231', '9999'], 1 not in array of values
template IN (valueArraySize){

        signal input in;
        signal input value[valueArraySize];
        signal output out;

        component eq[valueArraySize];
        var count = 0;
        for (var i=0; i<valueArraySize; i++) {
            eq[i] = IsEqual();
            eq[i].in[0] <== in;
            eq[i].in[1] <== value[i];
            count += eq[i].out;
        }

        // Greater then
        component gt = GreaterThan(252);
        gt.in[0] <== count;
        gt.in[1] <== 0;

        out <== gt.out; // 1 - if in signal in the list, 0 - if it is not
}

// As LessThan but for all possible numbers from field (not only 252-bit-max like LessThan)
template LessThan2() {
    signal input in[2];
    signal output out;

    component n0b = Num2Bits(256);
    n0b.in <== in[0];

    component n1b = Num2Bits(256);
    n1b.in <== in[1];

    // numbers for high 4 bits
    component h0  = Bits2Num(4);
    component h1  = Bits2Num(4);
    for(var i = 252; i < 256; i++) {
        h0.in[i-252] <== n0b.out[i];
        h1.in[i-252] <== n1b.out[i];
    }

    component hiBitLt = LessThan(4);
    hiBitLt.in[0] <== h0.out;
    hiBitLt.in[1] <== h1.out;
    component hiBitEq = IsEqual();
    hiBitEq.in[0] <== h0.out;
    hiBitEq.in[1] <== h1.out;
    component hiBitGt = GreaterThan(4);
    hiBitGt.in[0] <== h0.out;
    hiBitGt.in[1] <== h1.out;

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

    out <== (hiBitEq.out * lt.out) + (hiBitLt.out * 1) + (hiBitGt.out * 0);
}