pragma circom 2.1.1;

include "linked/multiQuery.circom";

component main {public [enabled]} = LinkedMultiQuery(3, 32, 64); // 50383 constraints
