pragma circom 2.1.1;

include "lib/stateTransition.circom";

component main {public [userID,oldUserState,newUserState,isOldStateGenesis]} = StateTransition(40);
