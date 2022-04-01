pragma circom 2.0.0;

include "../../circuits/lib/authentication.circom";

component main {public [challenge,state]} = VerifyAuthenticationInformation(4);
