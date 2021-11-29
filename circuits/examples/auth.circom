pragma circom 2.0.0;

include "../authentication.circom";

component main {public [id,challenge,state]} = VerifyAuthenticationInformation(4);
