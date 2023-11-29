pragma circom 2.1.1;

include "linked/multiQuery.circom";

component main {public [linkID]} = LinkedMultiQuery(10, 32, 64); // 114191 constraints
