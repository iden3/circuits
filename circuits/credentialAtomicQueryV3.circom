pragma circom 2.1.1;

include "offchain/credentialAtomicQueryV3OffChain.circom";

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
                       claimSchema,
                       slotIndex,
                       claimPathKey,
                       claimPathNotExists,
                       operator,
                       value,
                       timestamp, 
                       isRevocationChecked,
                       proofType,
                       verifierID,
                       verifierSessionID
                       ]} = credentialAtomicQueryV3OffChain(40, 32, 64);
