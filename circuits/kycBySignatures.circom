pragma circom 2.0.0;

include "kyc.circom";
include "idOwnershipBySignature.circom";
include "utils.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

// verifyKYCSignedCredentials proves validity of Country of Residence Claim
// and Birthday Claim, verifies they have allowed values (age >= 18 and country
// in not in the blacklist) and verifies they are signed by valid public keys of
// their issuers
template VerifyKYCSignedCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength) {

    /* id ownership signals */
	signal input id;
	signal input BBJAx;
	signal input BBJAy;
	signal input BBJClaimMtp[IdOwnershipLevels];
	signal input BBJClaimClaimsTreeRoot;
	signal input BBJClaimRevTreeRoot;
	signal input BBJClaimRootsTreeRoot;
	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    /* country claim signals */
	signal input countryClaim[8];
	signal input countryClaimIssuerId;
	signal input countryClaimIssuerBBJAx;
	signal input countryClaimIssuerBBJAy;
	signal input countryClaimIssuerBBJClaimMtp[IssuerLevels];
	signal input countryClaimIssuerBBJClaimClaimsTreeRoot;
	signal input countryClaimIssuerBBJClaimRevTreeRoot;
	signal input countryClaimIssuerBBJClaimRootsTreeRoot;
	signal input countryClaimIssuerBBJIdenState;
	signal input countryClaimSignatureR8x;
	signal input countryClaimSignatureR8y;
	signal input countryClaimSignatureS;
    // TODO: add non revocation check for issuer Public Key

    signal input countryBlacklist[CountryBlacklistLength];

    signal input countryClaimNonRevMtp[IssuerLevels];
    signal input countryClaimNonRevMtpNoAux;
    signal input countryClaimNonRevMtpAuxHi;
    signal input countryClaimNonRevMtpAuxHv;
    signal input countryClaimNonRevIssuerState;
    signal input countryClaimNonRevIssuerClaimsTreeRoot;
    signal input countryClaimNonRevIssuerRevTreeRoot;
    signal input countryClaimNonRevIssuerRootsTreeRoot;

    /* birthday claim signals */
	signal input birthdayClaim[8];
	signal input birthdayClaimIssuerId;
	signal input birthdayClaimIssuerBBJAx;
	signal input birthdayClaimIssuerBBJAy;
	signal input birthdayClaimIssuerBBJClaimMtp[IssuerLevels];
	signal input birthdayClaimIssuerBBJClaimClaimsTreeRoot;
	signal input birthdayClaimIssuerBBJClaimRevTreeRoot;
	signal input birthdayClaimIssuerBBJClaimRootsTreeRoot;
	signal input birthdayClaimIssuerBBJIdenState;
	signal input birthdayClaimSignatureR8x;
	signal input birthdayClaimSignatureR8y;
	signal input birthdayClaimSignatureS;
    // TODO: add non revocation check for issuer Public Key

    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    signal input minAge;

    signal input birthdayClaimNonRevMtp[IssuerLevels];
    signal input birthdayClaimNonRevMtpNoAux;
    signal input birthdayClaimNonRevMtpAuxHi;
    signal input birthdayClaimNonRevMtpAuxHv;
    signal input birthdayClaimNonRevIssuerState;
    signal input birthdayClaimNonRevIssuerClaimsTreeRoot;
    signal input birthdayClaimNonRevIssuerRevTreeRoot;
    signal input birthdayClaimNonRevIssuerRootsTreeRoot;

    /*****************************
        Id ownership check
    ******************************/

    //var challengeBE = bigEndian(challenge, 256);

    component userIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);
    userIdOwnership.id <== id;
    userIdOwnership.userPublicKeyAx <== BBJAx;
    userIdOwnership.userPublicKeyAy <== BBJAy;
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.siblings[i] <== BBJClaimMtp[i]; }
    userIdOwnership.claimsTreeRoot <== BBJClaimClaimsTreeRoot;
    userIdOwnership.revTreeRoot <== BBJClaimRevTreeRoot;
    userIdOwnership.rootsTreeRoot <== BBJClaimRootsTreeRoot;
    userIdOwnership.challenge <== challenge;
    userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    userIdOwnership.challengeSignatureS <== challengeSignatureS;


    /*****************************
        Country claim checks
    ******************************/

    // check that country claim with issuer public key is in it's identity state
    component verifyCountryClaimIssuerClaimKeyBBJJ = VerifyClaimKeyBBJJinIdState(IssuerLevels);
	verifyCountryClaimIssuerClaimKeyBBJJ.BBJAx <== countryClaimIssuerBBJAx;
	verifyCountryClaimIssuerClaimKeyBBJJ.BBJAy <== countryClaimIssuerBBJAy;
	for (var i=0; i<IssuerLevels; i++) {
		verifyCountryClaimIssuerClaimKeyBBJJ.siblings[i] <== countryClaimIssuerBBJClaimMtp[i];
	}
	verifyCountryClaimIssuerClaimKeyBBJJ.claimsTreeRoot <== countryClaimIssuerBBJClaimClaimsTreeRoot;
	verifyCountryClaimIssuerClaimKeyBBJJ.revTreeRoot <== countryClaimIssuerBBJClaimRevTreeRoot;
	verifyCountryClaimIssuerClaimKeyBBJJ.rootsTreeRoot <== countryClaimIssuerBBJClaimRootsTreeRoot;
    verifyCountryClaimIssuerClaimKeyBBJJ.idState <== countryClaimIssuerBBJIdenState;

    // verify that claim is signed with the provided public key,
    // claim is not revoked and revocation root is in issuer's state
    component verifyCountryClaim = verifyClaimIssuanceNonRevBySignature(IssuerLevels);
    for (var i=0; i<8; i++) { verifyCountryClaim.claim[i] <== countryClaim[i]; }
    verifyCountryClaim.id <== id;
    verifyCountryClaim.sigR8x <== countryClaimSignatureR8x;
    verifyCountryClaim.sigR8y <== countryClaimSignatureR8y;
    verifyCountryClaim.sigS <== countryClaimSignatureS;
    verifyCountryClaim.pubKeyX <== countryClaimIssuerBBJAx;
    verifyCountryClaim.pubKeyY <== countryClaimIssuerBBJAy;
    for (var i=0; i<IssuerLevels; i++) {
        verifyCountryClaim.claimNonRevMtp[i] <== countryClaimNonRevMtp[i];
    }
    verifyCountryClaim.claimNonRevMtpNoAux <== countryClaimNonRevMtpNoAux;
    verifyCountryClaim.claimNonRevMtpAuxHi <== countryClaimNonRevMtpAuxHi;
    verifyCountryClaim.claimNonRevMtpAuxHv <== countryClaimNonRevMtpAuxHv;
    verifyCountryClaim.claimNonRevIssuerClaimsTreeRoot <== countryClaimNonRevIssuerClaimsTreeRoot;
    verifyCountryClaim.claimNonRevIssuerRevTreeRoot <== countryClaimNonRevIssuerRevTreeRoot;
    verifyCountryClaim.claimNonRevIssuerRootsTreeRoot <== countryClaimNonRevIssuerRootsTreeRoot;
    verifyCountryClaim.claimNonRevIssuerState <== countryClaimNonRevIssuerState;

    // TODO: add schema check

    // get country value
    component country = getCountry();
    for (var i=0; i<8; i++) { country.claim[i] <== countryClaim[i]; }
    //country.country === 31
    component eq[CountryBlacklistLength];
    for (var i=0; i<CountryBlacklistLength; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== country.country;
        eq[i].in[1] <== countryBlacklist[i];
        eq[i].out === 0;
    }

    /*****************************
        Birthday claim checks
    ******************************/

    // check that birthday claim with issuer public key is in it's identity state
    component verifyBirthdayClaimIssuerClaimKeyBBJJ = VerifyClaimKeyBBJJinIdState(IssuerLevels);
	verifyBirthdayClaimIssuerClaimKeyBBJJ.BBJAx <== birthdayClaimIssuerBBJAx;
	verifyBirthdayClaimIssuerClaimKeyBBJJ.BBJAy <== birthdayClaimIssuerBBJAy;
	for (var i=0; i<IssuerLevels; i++) {
		verifyBirthdayClaimIssuerClaimKeyBBJJ.siblings[i] <== birthdayClaimIssuerBBJClaimMtp[i];
	}
	verifyBirthdayClaimIssuerClaimKeyBBJJ.claimsTreeRoot <== birthdayClaimIssuerBBJClaimClaimsTreeRoot;
	verifyBirthdayClaimIssuerClaimKeyBBJJ.revTreeRoot <== birthdayClaimIssuerBBJClaimRevTreeRoot;
	verifyBirthdayClaimIssuerClaimKeyBBJJ.rootsTreeRoot <== birthdayClaimIssuerBBJClaimRootsTreeRoot;
    verifyBirthdayClaimIssuerClaimKeyBBJJ.idState <== birthdayClaimIssuerBBJIdenState;

    // verify that claim is signed with the provided public key,
    // claim is not revoked and revocation root is in issuer's state
    component verifyBirthdayClaim = verifyClaimIssuanceNonRevBySignature(IssuerLevels);
    for (var i=0; i<8; i++) { verifyBirthdayClaim.claim[i] <== birthdayClaim[i]; }
    verifyBirthdayClaim.id <== id;
    verifyBirthdayClaim.sigR8x <== birthdayClaimSignatureR8x;
    verifyBirthdayClaim.sigR8y <== birthdayClaimSignatureR8y;
    verifyBirthdayClaim.sigS <== birthdayClaimSignatureS;
    verifyBirthdayClaim.pubKeyX <== birthdayClaimIssuerBBJAx;
    verifyBirthdayClaim.pubKeyY <== birthdayClaimIssuerBBJAy;
    for (var i=0; i<IssuerLevels; i++) {
        verifyBirthdayClaim.claimNonRevMtp[i] <== birthdayClaimNonRevMtp[i];
    }
    verifyBirthdayClaim.claimNonRevMtpNoAux <== birthdayClaimNonRevMtpNoAux;
    verifyBirthdayClaim.claimNonRevMtpAuxHi <== birthdayClaimNonRevMtpAuxHi;
    verifyBirthdayClaim.claimNonRevMtpAuxHv <== birthdayClaimNonRevMtpAuxHv;
    verifyBirthdayClaim.claimNonRevIssuerClaimsTreeRoot <== birthdayClaimNonRevIssuerClaimsTreeRoot;
    verifyBirthdayClaim.claimNonRevIssuerRevTreeRoot <== birthdayClaimNonRevIssuerRevTreeRoot;
    verifyBirthdayClaim.claimNonRevIssuerRootsTreeRoot <== birthdayClaimNonRevIssuerRootsTreeRoot;
    verifyBirthdayClaim.claimNonRevIssuerState <== birthdayClaimNonRevIssuerState;

    // TODO: add schema check

    // get birthday value
    component birthday = getBirthday();
    for (var i=0; i<8; i++) { birthday.claim[i] <== birthdayClaim[i]; }

    // calculate age
	component age = calculateAge();
	age.DOBYear <== birthday.year;
	age.DOBMonth <== birthday.month;
	age.DOBDay <== birthday.day;
	age.CurYear <== currentYear;
	age.CurMonth <== currentMonth;
	age.CurDay <== currentDay;

//    component age = getAge();
//    for (var i=0; i<8; i++) { age.claim[i] <== birthdayClaim[i]; }

    // verify age > minAge
    component gte18 = GreaterEqThan(32);
    gte18.in[0] <== age.age;
    gte18.in[1] <== minAge;
    gte18.out === 1;

}
