pragma circom 2.0.0;

include "lib/stateTransition.circom";

component main {public [userID,oldUserState,newUserState]} = StateTransition(40);
