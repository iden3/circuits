pragma circom 2.0.0;

include "../../../circuits/lib/query/query.circom";

component main { public [value] } = Query(3);
