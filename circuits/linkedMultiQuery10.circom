pragma circom 2.1.1;

include "linked/multiQuery.circom";

component main {public [valueArraySize]} = LinkedMultiQuery(10, 32, 64); // 164791 constraints
