pragma circom 2.0.0;

include "../idState.circom";

component main {public [id,oldIdState,newIdState]} = IdState(4);
