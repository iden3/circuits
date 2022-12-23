pragma circom 2.0.0;

include "credentialAtomicQuerySigOnChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
 issuerAuthState
*/
component main{public [issuerID,
                       issuerClaimNonRevState,
                       claimSchema,
                       slotIndex,
                       claimPathKey,
                       claimPathNotExists,
                       operator,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot]} = credentialAtomicQuerySigOnChain(32, 32, 64, 32, 32);
