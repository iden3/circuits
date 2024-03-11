pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";
include "../../../circuits/lib/utils/tags-managing.circom";

template wrappedIsUpdatable() {
    signal input claimFlags[32];
    signal output out;

    component check = isUpdatable();
    check.claimFlags <== AddBinaryArrayTag(32)(claimFlags);
    out <== check.out;
}

component main = wrappedIsUpdatable();
