pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtils.circom";
include "../../../circuits/lib/utils/treeUtils.circom";
include "../../../circuits/lib/utils/tags-managing.circom";

template wrappedCheckIdenStateMatchesRoots(){
    signal input enabled;
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;
	signal input expectedState;

    component check = checkIdenStateMatchesRoots();
    check.enabled <== AddBinaryTag()(enabled);
    check.claimsTreeRoot <== claimsTreeRoot;
    check.revTreeRoot <== revTreeRoot;
    check.rootsTreeRoot <== rootsTreeRoot;
    check.expectedState <== expectedState;
}

component main = wrappedCheckIdenStateMatchesRoots();
