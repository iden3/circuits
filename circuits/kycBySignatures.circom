include "kyc.circom"
include "idOwnershipBySignature.circom"
include "utils.circom"
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

// verifyKYCSignedCredentials proves validity of Country of Residence Claim
// and Birthday Claim, verifies they have allowed values (age >= 18 and country
// in not in the blacklist) and verifies they are signed by valid public keys of
// their issuers
template VerifyKYCSignedCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength) {

    /* id ownership signals */
	signal private input id;
	signal private input BBJAx;
	signal private input BBJAy;
	signal private input BBJClaimMtp[IdOwnershipLevels];
	signal private input BBJClaimClaimsTreeRoot;
	signal private input BBJClaimRevTreeRoot;
	signal private input BBJClaimRootsTreeRoot;
	signal input challenge;
	signal private input challengeSignatureR8x;
	signal private input challengeSignatureR8y;
	signal private input challengeSignatureS;

    /* country claim signals */
	signal private input countryClaim[8];
	signal input countryClaimIssuerId;
	signal private input countryClaimIssuerBBJAx;
	signal private input countryClaimIssuerBBJAy;
	signal private input countryClaimIssuerBBJClaimMtp[IssuerLevels];
	signal private input countryClaimIssuerBBJClaimClaimsTreeRoot;
	signal private input countryClaimIssuerBBJClaimRevTreeRoot;
	signal private input countryClaimIssuerBBJClaimRootsTreeRoot;
	signal input countryClaimIssuerBBJIdenState;
	signal private input countryClaimSignatureR8x;
	signal private input countryClaimSignatureR8y;
	signal private input countryClaimSignatureS;
    // TODO: add non revocation check for issuer Public Key

    signal input countryBlacklist[CountryBlacklistLength]

    // TODO: add non revocation checks
    //	signal private input countryClaimNotRevMtp[IssuerLevels];
    //	signal private input countryClaimNotRevMtpNoAux;
    //	signal private input countryClaimNotRevMtpAuxHi;
    //	signal private input countryClaimNotRevMtpAuxHv;

    /* birthday claim signals */
	signal private input birthdayClaim[8];
	signal input birthdayClaimIssuerId;
	signal private input birthdayClaimIssuerBBJAx;
	signal private input birthdayClaimIssuerBBJAy;
	signal private input birthdayClaimIssuerBBJClaimMtp[IssuerLevels];
	signal private input birthdayClaimIssuerBBJClaimClaimsTreeRoot;
	signal private input birthdayClaimIssuerBBJClaimRevTreeRoot;
	signal private input birthdayClaimIssuerBBJClaimRootsTreeRoot;
	signal input birthdayClaimIssuerBBJIdenState;
	signal private input birthdayClaimSignatureR8x;
	signal private input birthdayClaimSignatureR8y;
	signal private input birthdayClaimSignatureS;
    // TODO: add non revocation check for issuer Public Key

    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    signal input minAge;

    // TODO: add non revocation checks
    //	signal private input birthdayClaimNotRevMtp[IssuerLevels];
    //	signal private input birthdayClaimNotRevMtpNoAux;
    //	signal private input birthdayClaimNotRevMtpAuxHi;
    //	signal private input birthdayClaimNotRevMtpAuxHv;

    /*
        Id ownership check
    */

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


    /*
        Country claim checks
    */
    // check country claim is issued to provided identity
    component countryClaimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { countryClaimIdCheck.claim[i] <== countryClaim[i]; }
    countryClaimIdCheck.id <== id;

    // TODO: add schema check

    // check that country claim with issuer public key is in it's identity state
    component verifyCountryClaimIssuerClaimKeyBBJJ = VerifyClaimKeyBBJJinIdState(IssuerLevels)
	verifyCountryClaimIssuerClaimKeyBBJJ.BBJAx <== countryClaimIssuerBBJAx;
	verifyCountryClaimIssuerClaimKeyBBJJ.BBJAy <== countryClaimIssuerBBJAy;
	for (var i=0; i<IssuerLevels; i++) {
		verifyCountryClaimIssuerClaimKeyBBJJ.siblings[i] <== countryClaimIssuerBBJClaimMtp[i];
	}
	verifyCountryClaimIssuerClaimKeyBBJJ.claimsTreeRoot <== countryClaimIssuerBBJClaimClaimsTreeRoot;
	verifyCountryClaimIssuerClaimKeyBBJJ.revTreeRoot <== countryClaimIssuerBBJClaimRevTreeRoot;
	verifyCountryClaimIssuerClaimKeyBBJJ.rootsTreeRoot <== countryClaimIssuerBBJClaimRootsTreeRoot;
    verifyCountryClaimIssuerClaimKeyBBJJ.idState <== countryClaimIssuerBBJIdenState;

    // check country claim signature
    component verifyCountryClaimSignature = verifyClaimSignature();
    for (var i=0; i<8; i++) { verifyCountryClaimSignature.claim[i] <== countryClaim[i]; }
	verifyCountryClaimSignature.sigR8x <== countryClaimSignatureR8x;
	verifyCountryClaimSignature.sigR8y <== countryClaimSignatureR8y;
	verifyCountryClaimSignature.sigS <== countryClaimSignatureS;
	verifyCountryClaimSignature.pubKeyX <== countryClaimIssuerBBJAx;
	verifyCountryClaimSignature.pubKeyY <== countryClaimIssuerBBJAy;


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

    /*
        Birthday claim checks
    */
    // check birthday claim is issued to provided identity
    component birthdayClaimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { birthdayClaimIdCheck.claim[i] <== birthdayClaim[i]; }
    birthdayClaimIdCheck.id <== id;

    // TODO: add schema check

    // check that birthday claim with issuer public key is in it's identity state
    component verifyBirthdayClaimIssuerClaimKeyBBJJ = VerifyClaimKeyBBJJinIdState(IssuerLevels)
	verifyBirthdayClaimIssuerClaimKeyBBJJ.BBJAx <== birthdayClaimIssuerBBJAx;
	verifyBirthdayClaimIssuerClaimKeyBBJJ.BBJAy <== birthdayClaimIssuerBBJAy;
	for (var i=0; i<IssuerLevels; i++) {
		verifyBirthdayClaimIssuerClaimKeyBBJJ.siblings[i] <== birthdayClaimIssuerBBJClaimMtp[i];
	}
	verifyBirthdayClaimIssuerClaimKeyBBJJ.claimsTreeRoot <== birthdayClaimIssuerBBJClaimClaimsTreeRoot;
	verifyBirthdayClaimIssuerClaimKeyBBJJ.revTreeRoot <== birthdayClaimIssuerBBJClaimRevTreeRoot;
	verifyBirthdayClaimIssuerClaimKeyBBJJ.rootsTreeRoot <== birthdayClaimIssuerBBJClaimRootsTreeRoot;
    verifyBirthdayClaimIssuerClaimKeyBBJJ.idState <== birthdayClaimIssuerBBJIdenState;

    // check birthday claim signature
    component verifyBirthdayClaimSignature = verifyClaimSignature();
    for (var i=0; i<8; i++) { verifyBirthdayClaimSignature.claim[i] <== birthdayClaim[i]; }
	verifyBirthdayClaimSignature.sigR8x <== birthdayClaimSignatureR8x;
	verifyBirthdayClaimSignature.sigR8y <== birthdayClaimSignatureR8y;
	verifyBirthdayClaimSignature.sigS <== birthdayClaimSignatureS;
	verifyBirthdayClaimSignature.pubKeyX <== birthdayClaimIssuerBBJAx;
	verifyBirthdayClaimSignature.pubKeyY <== birthdayClaimIssuerBBJAy;

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
