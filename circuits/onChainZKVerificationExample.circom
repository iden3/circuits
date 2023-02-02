pragma circom 2.0.0;

include "./onChainZKVerificationExample/onChainZKVerificationExample.circom";

component main {public [issuerPubKeyAx, issuerPubKeyAy, userEthereumAddressInClaim, userMinAge]} = OnChainZKVerificationExample();
