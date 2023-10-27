pragma circom 2.1.1;

include "./onchain/credentialAtomicQuerySigOnChain.circom";

component main{public [requestID,
                       issuerID,
                       issuerClaimNonRevState,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot]} = credentialAtomicQuerySigOnChain(40, 32, 64, 40, 64);
