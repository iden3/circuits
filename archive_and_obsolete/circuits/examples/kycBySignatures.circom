pragma circom 2.0.0;

include "../kycBySignatures.circom";

// VerifyKYCSignedCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength)
component main {public [
    challenge,
    countryClaimIssuerId,
    countryClaimIssuerBBJIdenState,
    countryBlacklist,
    birthdayClaimIssuerId,
    birthdayClaimIssuerBBJIdenState,
    currentYear,
    currentMonth,
    currentDay
]} = VerifyKYCSignedCredentials(4, 40, 16);
