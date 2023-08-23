pragma circom 2.1.1;

include "../../../circuits/lib/query/query.circom";

component main { public [value] } = Query(3);
