pragma circom 2.0.0;

include "lib/authentication.circom";

component main {public [id,challenge,state]} = VerifyAuthentication(40);
