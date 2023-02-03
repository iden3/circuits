pragma circom 2.0.0;

include "./onchain/credentialAtomicQueryMTPOnChain.circom";

component main{public [requestID,
                       issuerID,
                       issuerClaimIdenState,
                       issuerClaimNonRevState,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot
                       ]} = CredentialAtomicQueryMTPOnChain(32, 32, 64, 32, 32);
