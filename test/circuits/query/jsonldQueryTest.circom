pragma circom 2.0.0;

include "../../../circuits/lib/query/jsonldQuery.circom";

component main { public [value] } = JsonLDQuery(3, 40);
