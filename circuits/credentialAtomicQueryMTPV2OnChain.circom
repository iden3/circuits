pragma circom 2.0.0;

include "./onchain/credentialAtomicQueryMTPOnChain.circom";

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
                       ]} = CredentialAtomicQueryMTPOnChain(40, 32, 64, 40, 64);
