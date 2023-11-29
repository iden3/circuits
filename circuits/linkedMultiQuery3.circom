pragma circom 2.1.1;

include "linked/multiQuery.circom";

component main {public [linkID]} = LinkedMultiQuery(3, 32, 64); // 34447 constraints
