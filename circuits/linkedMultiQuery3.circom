pragma circom 2.1.1;

include "linked/multiQuery.circom";

component main = LinkedMultiQuery(3, 32, 64); // N, claimLevels, maxValueArraySize
