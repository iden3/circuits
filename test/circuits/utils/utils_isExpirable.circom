pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";
include "../../../circuits/lib/utils/tags-managing.circom";

template wrappedIsExpirable() {
    signal input claimFlags[32];
    signal output out;

    component check = isExpirable();
    check.claimFlags <== AddBinaryArrayTag(32)(claimFlags);
    out <== check.out;
}

component main = wrappedIsExpirable();
