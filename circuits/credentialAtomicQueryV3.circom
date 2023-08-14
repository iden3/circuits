pragma circom 2.1.1;

include "offchain/credentialAtomicQueryV3OffChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
 issuerAuthState // for sig
 issuerClaimIdenState // for mtp
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
                       issuerClaimIdenState, // MTP specific
                       proofType]} = credentialAtomicQueryV3OffChain(40, 32, 64);
