pragma circom 2.0.0;

include "credentialAtomicQueryMTPOnChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
*/
component main{public [issuerID,
                       issuerClaimIdenState,
                       issuerClaimNonRevState,
                       claimSchema,
                       slotIndex,
                       claimPathKey,
                       claimPathNotExists,
                       operator,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot
                       ]} = CredentialAtomicQueryMTPOnChain(32, 32, 64, 32, 32);
