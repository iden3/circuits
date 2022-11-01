pragma circom 2.0.0;

include "lib/auth.circom";

component main {public [userID,challenge,userState]} = Auth(32);
