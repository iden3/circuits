pragma circom 2.0.0;

include "./onchain/credentialAtomicQuerySigOnChain.circom";

component main{public [requestID,
                       issuerID,
                       issuerClaimNonRevState,
                       claimPathKey,
                       claimPathNotExists,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot]} = credentialAtomicQuerySigOnChain(40, 32, 64, 40, 64);
