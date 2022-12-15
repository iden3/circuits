pragma circom 2.0.0;

include "utils/claimUtils.circom";
include "utils/treeUtils.circom";

template TreeTest(nLevels) {
    signal input mtp[nLevels];
    signal input claim[8];
    signal input root;

    signal output out;

    component testTree = checkClaimExists(nLevels);
    for (var i=0; i<8; i++) { testTree.claim[i] <== claim[i]; }
    for (var i=0; i<nLevels; i++) { testTree.claimMTP[i] <== mtp[i]; }
    testTree.treeRoot <== root;

    out <== 0;
}