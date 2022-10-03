pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "comparators.circom";

/*
  Operators:
 "0" - noop, skip execution. Ignores all `in` and `value` passed to query, out 1
 "1" - equals
 "2" - less-than
 "3" - greater-than
 "4" - in
 "5" - notin
*/
template JsonLDQuery (valueArraySize, mtLevel) {
    // signals
    signal input jsonldRoot;
    // proof
    signal input notExists; // 0 for inclusion, 1 for non-inclusion
    signal input mtp[mtLevel];
    signal input auxNodeKey; // 0 for inclusion proof
    signal input auxNodeValue; // 0 for inclusion proof
    signal input auxNodeEmpty; // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
    // hash of path in merklized json-ld document
    signal input path;
    // value in this path in merklized json-ld document
    signal input in;
    signal input value[valueArraySize];
    signal input operator;
    signal output out;
    // for checkClaimExists

    // check path/in node exists in merkletree specified by jsonldRoot
    component valueInMT = SMTVerifier(mtLevel);
    valueInMT.enabled <== 1;
    valueInMT.fnc <== notExists; // inclusion
    valueInMT.root <== jsonldRoot;
    for (var i=0; i<mtLevel; i++) { valueInMT.siblings[i] <== mtp[i]; }
    valueInMT.oldKey <== auxNodeKey;
    valueInMT.oldValue <== auxNodeValue;
    valueInMT.isOld0 <== auxNodeEmpty;
    valueInMT.key <== path;
    valueInMT.value <== in;

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

    mux.c[0] <== 1; // noop, skip execution
    mux.c[1] <== eq.out;
    mux.c[2] <== lt.out;
    mux.c[3] <== gt.out;
    mux.c[4] <== inComp.out;

    mux.c[5] <== 1-inComp.out;

    mux.c[6] <== 0; // not in use
    mux.c[7] <== 0; // not in use

    // output
    out <== mux.out;
}
