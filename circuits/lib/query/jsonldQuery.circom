pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "comparators.circom";
include "query.circom";

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

    component query = Query(valueArraySize);
    query.in <== in;
    for (var i=0; i<valueArraySize; i++) { query.value[i] <== value[i]; }
    query.operator <== operator;
    out <== query.out;
}
