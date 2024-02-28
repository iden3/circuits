pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";
include "../../../circuits/lib/utils/tags-managing.circom";

template wrappedGetClaimMerklizeRoot() {
    signal input claim[8];
    signal input claimFlags[32];
    signal output flag;
    signal output out;

    component check = getClaimMerklizeRoot();
    check.claim <== claim;
    check.claimFlags <== AddBinaryArrayTag(32)(claimFlags);
    flag <== check.flag;
    out <== check.out;
}

component main = wrappedGetClaimMerklizeRoot();
