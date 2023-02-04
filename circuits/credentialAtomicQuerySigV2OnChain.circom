pragma circom 2.0.0;

include "./onchain/credentialAtomicQuerySigOnChain.circom";

component main{public [requestID,
                       issuerID,
                       issuerClaimNonRevState,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot]} = credentialAtomicQuerySigOnChain(32, 32, 64, 32, 32);
