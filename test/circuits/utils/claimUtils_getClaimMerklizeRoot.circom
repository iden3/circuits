pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";
include "../../../circuits/lib/utils/tags-managing.circom";

template wrappedGetClaimMerklizeRoot() {
    signal input claim[8];
    signal input claimFlags[32];
    signal output flag;
    signal output out;

    component getClaimMerklizeRoot = GetClaimMerklizeRoot();
    getClaimMerklizeRoot.claim <== claim;
    getClaimMerklizeRoot.claimFlags <== AddBinaryArrayTag()(claimFlags);
    flag <== getClaimMerklizeRoot.flag;
    out <== getClaimMerklizeRoot.out;
}

component main = wrappedGetClaimMerklizeRoot();
