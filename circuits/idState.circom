pragma circom 2.0.0;

include "lib/idState.circom";

component main {public [id,oldIdState,newIdState]} = IdState(40);
