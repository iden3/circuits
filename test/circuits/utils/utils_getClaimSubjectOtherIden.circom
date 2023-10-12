pragma circom 2.1.1;

include "../../../circuits/lib/utils/claimUtilsWrappers.circom";

component main{public[claim]} = getClaimSubjectOtherIdenWrapper();
