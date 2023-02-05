pragma circom 2.0.0;

include "auth/authV2.circom";

/*
* The identity authorization circuit.
* User ownership of the identity verified by signed challenge.
* Auth claim should be in the user state and not revoked.
* User state should be genesis or added to the global state tree (available in the smart contract).
* The state is verified out of circuits by a verifier.
* public signals:
    - userID
    - challenge
    - gistRoot
*/
component main {public [challenge, gistRoot]} = AuthV2(32,32);
