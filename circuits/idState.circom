
/*
# idState.circom

Circuit to check:
- prover is owner of the private key
- prover public key is in a ClaimKAuthBBJJ that is inside the IdState

                         +---------+
PRI_UserPrivateKey+----->+ pvk2pbk |
                +        +----+----+
                |             |
                |             |
                |             v
                |       +-----+--------------+                          +----------+
                |       |                    |    +----------+          |          +<---------+PRI_MTP
                |       | pbk2ClaimKAuthBBJJ +--->+          |hi +----->+          |
                |       |                    |    | Poseidon |          | SMT      |
                |       +--------------------+    |          |hv +----->+ Poseidon |
                |                                 +----------+          | Verifier +<---------+PUB_ClaimsTreeRoot
                |                                                       |          |             +
                |         +----------+                                  |          |             |
                +-------->+          |                                  +----------+             |
                          |          |                                                           |
 PUB_OldIdState+--------->+ Poseidon |                                  +---------+              |
                          |          +<----------+        +----+        |         +<-------------+
                          |          |           |        | == +<-------+         |
                          +----+-----+           |        +-+--+        |  ID     +<------------+PUB_RevTreeRoot
                               |                 |          ^           |  State  |
                               v                 |          |           |         +<------------+PUB_RootsTreeRoot
                             +-+--+              |          |           |         |
       PUB_Nullifier+------->+ == |              |          |           +---------+
                             +----+              |          |
                                                 |          +              +----+
                                                 +----+PUB_IdState+------->+ != +<------+0
                                                                           +----+




*/

