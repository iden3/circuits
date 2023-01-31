pragma circom 2.0.0;

include "./onchain/credentialAtomicQueryMTPOnChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
*/
component main{public [requestID,
                       issuerID,
                       issuerClaimIdenState,
                       issuerClaimNonRevState,
                       claimPathKey,
                       claimPathNotExists,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot
                       ]} = CredentialAtomicQueryMTPOnChain(32, 32, 64, 32, 32);
