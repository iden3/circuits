pragma circom 2.0.0;

include "../../../circuits/lib/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                       userID,
                       userState,
                       сlaimSchema,
                       issuerID,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = CredentialAtomicQueryMTP(40, 40, 16);
