include "credential.circom"

// verifyKYCCredentials proves ownership and validity of Country of Residence Claim
// and Birthday Claim and verifies they have allowed values (age >= 18 and country
// in not in the blacklist)
template verifyKYCCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength) {

    /* id ownership signals */
	signal private input id;
	signal private input userPrivateKey;
	signal private input BBJClaimMtp[IdOwnershipLevels];
	signal private input BBJClaimClaimsTreeRoot;
	// signal private input BBJClaimRevTreeRoot;
	// signal private input BBJClaimRootsTreeRoot;

    /* country claim signals */
	signal private input countryClaim[8];
	signal private input countryClaimIssuanceMtp[IssuerLevels];
	signal private input countryClaimIssuanceClaimsTreeRoot;
	signal private input countryClaimIssuanceRevTreeRoot;
	signal private input countryClaimIssuanceRootsTreeRoot;
	signal input countryClaimIssuanceIdenState;

    signal input countryBlacklist[CountryBlacklistLength]

    // TODO: add non revocation checks
    //	signal private input countryClaimNotRevMtp[IssuerLevels];
    //	signal private input countryClaimNotRevMtpNoAux;
    //	signal private input countryClaimNotRevMtpAuxHi;
    //	signal private input countryClaimNotRevMtpAuxHv;

    /* birthday claim signals */
	signal private input birthdayClaim[8];
	signal private input birthdayClaimIssuanceMtp[IssuerLevels];
	signal private input birthdayClaimIssuanceClaimsTreeRoot;
	signal private input birthdayClaimIssuanceRevTreeRoot;
	signal private input birthdayClaimIssuanceRootsTreeRoot;
	signal input birthdayClaimIssuanceIdenState;

    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    signal input challenge;

    // TODO: add non revocation checks
    //	signal private input birthdayClaimNotRevMtp[IssuerLevels];
    //	signal private input birthdayClaimNotRevMtpNoAux;
    //	signal private input birthdayClaimNotRevMtpAuxHi;
    //	signal private input birthdayClaimNotRevMtpAuxHv;

    /*
        Id ownership check
    */
    // TODO: switch to IdOwnership template
    component userIdOwnership = IdOwnershipGenesis(IdOwnershipLevels);
    userIdOwnership.id <== id;
    userIdOwnership.userPrivateKey <== userPrivateKey;
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.siblings[i] <== BBJClaimMtp[i]; }
    userIdOwnership.claimsTreeRoot <== BBJClaimClaimsTreeRoot;

    /*
        Country claim checks
    */
    // check country claim is issued to provided identity
    component countryClaimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { countryClaimIdCheck.claim[i] <== countryClaim[i]; }
    countryClaimIdCheck.id <== id;

    // TODO: add schema check

    component verifyCountryClaimIssuance = verifyClaimIssuance(IssuerLevels);
    for (var i=0; i<8; i++) { verifyCountryClaimIssuance.claim[i] <== countryClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyCountryClaimIssuance.claimIssuanceMtp[i] <== countryClaimIssuanceMtp[i]; }
    verifyCountryClaimIssuance.claimIssuanceClaimsTreeRoot <== countryClaimIssuanceClaimsTreeRoot;
    verifyCountryClaimIssuance.claimIssuanceRevTreeRoot <== countryClaimIssuanceRevTreeRoot;
    verifyCountryClaimIssuance.claimIssuanceRootsTreeRoot <== countryClaimIssuanceRootsTreeRoot;
    verifyCountryClaimIssuance.claimIssuanceIdenState <== countryClaimIssuanceIdenState;

    // get country value
    component country = getCountry();
    for (var i=0; i<8; i++) { country.claim[i] <== countryClaim[i]; }
    //country.country === 31
    component eq[CountryBlacklistLength];
    for (var i=0; i<CountryBlacklistLength; i++) {
        eq[i] = IsEqual()
        eq[i].in[0] <== country.country
        eq[i].in[1] <== countryBlacklist[i]
        eq[i].out === 0
    }

    /*
        Birthday claim checks
    */
    // check birthday claim is issued to provided identity
    component birthdayClaimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { birthdayClaimIdCheck.claim[i] <== birthdayClaim[i]; }
    birthdayClaimIdCheck.id <== id;

    // TODO: add schema check

    component verifyBirthdayClaimIssuance = verifyClaimIssuance(IssuerLevels);
    for (var i=0; i<8; i++) { verifyBirthdayClaimIssuance.claim[i] <== birthdayClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyBirthdayClaimIssuance.claimIssuanceMtp[i] <== birthdayClaimIssuanceMtp[i]; }
    verifyBirthdayClaimIssuance.claimIssuanceClaimsTreeRoot <== birthdayClaimIssuanceClaimsTreeRoot;
    verifyBirthdayClaimIssuance.claimIssuanceRevTreeRoot <== birthdayClaimIssuanceRevTreeRoot;
    verifyBirthdayClaimIssuance.claimIssuanceRootsTreeRoot <== birthdayClaimIssuanceRootsTreeRoot;
    verifyBirthdayClaimIssuance.claimIssuanceIdenState <== birthdayClaimIssuanceIdenState;

//    // get birthday value
//    component birthday = getBirthday();
//    for (var i=0; i<8; i++) { birthday.claim[i] <== birthdayClaim[i]; }
//
//    // calculate age
//	component age = calculateAge();
//	age.DOBYear <== birthday.year;
//	age.DOBMonth <== birthday.month;
//	age.DOBDay <== birthday.day;
//	age.CurYear <== currentYear;
//	age.CurMonth <== currentMonth;
//	age.CurDay <== currentDay;

    component age = getAge();
    for (var i=0; i<8; i++) { age.claim[i] <== birthdayClaim[i]; }

    // verify age > 18
    component gte18 = GreaterEqThan(32);
    gte18.in[0] <== age.age;
    gte18.in[1] <== 18;
    gte18.out === 1;

}

// getBirthday gets the country from a country claim
template getCountry() {
	signal input claim[8];
	signal output country;

 	component i0 = Num2Bits(256);
	i0.in <== claim[0];

	component num = Bits2Num(256);

    // copy 32 bits starting from position 160 (should be 96?)
	for (var i=0; i<32; i++) {
		num.in[i] <== i0.out[i+160];
	}
	for (var i=32; i<256; i++) {
		num.in[i] <== 0;
	}
	country <== num.out;
}

// getBirthday gets the country from a country claim
template getBirthday() {
	signal input claim[8];
	signal output year;
	signal output month;
	signal output day;

 	component i0 = Num2Bits(256);
	i0.in <== claim[0];

	component numY = Bits2Num(256);

    // copy 32 bits starting from position 160 (should be 96?)
	for (var i=0; i<32; i++) {
		numY.in[i] <== i0.out[i+160];
	}
	for (var i=32; i<256; i++) {
		numY.in[i] <== 0;
	}
	year <== numY.out;
	
	component numM = Bits2Num(256);

    // copy 32 bits starting from position 160 (should be 96?)
	for (var i=0; i<32; i++) {
		numM.in[i] <== i0.out[i+192];
	}
	for (var i=32; i<256; i++) {
		numM.in[i] <== 0;
	}
	month <== numM.out;
	
	component numD = Bits2Num(256);

    // copy 32 bits starting from position 160 (should be 96?)
	for (var i=0; i<32; i++) {
		numD.in[i] <== i0.out[i+224];
	}
	for (var i=32; i<256; i++) {
		numD.in[i] <== 0;
	}
	day <== numD.out;
}

// getAge gets age from an age claim
template getAge() {
	signal input claim[8];
	signal output age;

 	component i0 = Num2Bits(256);
	i0.in <== claim[0];

	component numY = Bits2Num(256);

    // copy 32 bits starting from position 160 (should be 96?)
	for (var i=0; i<32; i++) {
		numY.in[i] <== i0.out[i+160];
	}
	for (var i=32; i<256; i++) {
		numY.in[i] <== 0;
	}
	age <== numY.out;
}

template calculateAge() {
	signal input DOBYear;
	signal input DOBMonth;
	signal input DOBDay;
	signal input CurYear;
	signal input CurMonth;
	signal input CurDay;
	signal output age;

    component validDOB = validateDate();
    validDOB.year <== DOBYear;
    validDOB.month <== DOBMonth;
    validDOB.day <== DOBDay;

    component validCurDate = validateDate();
    validCurDate.year <== CurYear;
    validCurDate.month <== CurMonth;
    validCurDate.day <== CurDay;

    component gteY = GreaterEqThan(32)
    gteY.in[0] <== CurYear;
    gteY.in[1] <== DOBYear;
    gteY.out === 1;

    var yearDiff = CurYear - DOBYear;

    // TODO: changing yearDiff inside if was not working, ask Jordi why
    signal tmp_age;
    if ((CurMonth < DOBMonth) || ((CurMonth == DOBMonth) && (CurDay < DOBDay))) {
        tmp_age <-- yearDiff - 1;
    } else {
        tmp_age <-- yearDiff;
    }

    component gte0 = GreaterEqThan(32);
    gte0.in[0] <== tmp_age;
    gte0.in[1] <== 0;
    gte0.out === 1;

    age <== tmp_age;
}

template validateDate() {
    signal input year;
    signal input month;
    signal input day;

    component yearGte1900 = GreaterEqThan(32);
    yearGte1900.in[0] <== year;
    yearGte1900.in[1] <== 1900;
    yearGte1900.out === 1;

    component yearLte2100 = LessEqThan(32);
    yearLte2100.in[0] <== year;
    yearLte2100.in[1] <== 2100;
    yearLte2100.out === 1;

    component monthGte1 = GreaterEqThan(32);
    monthGte1.in[0] <== month;
    monthGte1.in[1] <== 1;
    monthGte1.out === 1;

    component monthLte12 = LessEqThan(32);
    monthLte12.in[0] <== month;
    monthLte12.in[1] <== 12;
    monthLte12.out === 1;

    component dayGte1 = GreaterEqThan(32);
    dayGte1.in[0] <== day;
    dayGte1.in[1] <== 1;
    dayGte1.out === 1;

    component dayLte31 = LessEqThan(32);
    dayLte31.in[0] <== day;
    dayLte31.in[1] <== 31;
    dayLte31.out === 1;
}
