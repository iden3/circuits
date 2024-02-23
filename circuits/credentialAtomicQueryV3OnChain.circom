pragma circom 2.1.1;

include "./onchain/credentialAtomicQueryV3OnChain.circom";

/*
 public output signals:
 userID - user profile id
 merklized - `1` if claim is merklized
 issuerState - equals to issuerAuthState for sig, and to issuerClaimIdenState for mtp
 nullifier - sybil resistant user identifier for session id
 linkID - linked proof identifier
*/
component main{public [requestID,
                       issuerID,
                       issuerClaimNonRevState,
                       timestamp,
                       challenge,
                       gistRoot,
                       proofType,
                       isBJJAuthEnabled
                       ]} = credentialAtomicQueryV3OnChain(40, 32, 64, 40, 64);
