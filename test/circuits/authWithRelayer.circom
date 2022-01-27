pragma circom 2.0.0;

include "../../circuits/authenticationWithRelayer.circom";

component main {public [challenge,state]} = VerifyAuthenticationInformationWithRelayer(40, 4);
