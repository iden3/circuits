pragma circom 2.0.0;

include "../../../circuits/lib/query/credentialJsonLDAtomicQueryMTP.circom";

component main{public [challenge,
                       userID,
                       userState,
                       claimSchema,
                       issuerID,
                       claimPathKey,
                       operator,
                       value,
                       timestamp]} = CredentialJsonLDAtomicQueryMTP(32, 32, 32, 64);
