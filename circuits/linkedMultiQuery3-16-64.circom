pragma circom 2.1.1;

include "linked/multiQuery.circom";

component main = LinkedMultiQuery(3, 16, 64); // N, claimLevels, maxValueArraySize
