pragma circom 2.1.1;

include "./onchain/credentialAtomicQueryMTPOnChain.circom";

component main{public [requestID,
                       issuerID,
                       issuerClaimIdenState,
                       issuerClaimNonRevState,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot
                       ]} = CredentialAtomicQueryMTPOnChain(40, 32, 64, 40, 64);
