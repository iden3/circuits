include "../kycBySignatures.circom"

// VerifyKYCSignedCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength)
component main = VerifyKYCSignedCredentials(4, 40, 16);
