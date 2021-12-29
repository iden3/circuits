pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "date.circom";

template calculateAgeFromYYYYMMDD(){
	signal input yyyymmdd;

	signal input currentYear;
	signal input currentMonth;
	signal input currentDay;

	signal output age;

    component date = getDateFromYYYYMMDD();
    date.yyyymmdd <== yyyymmdd;

	component calcAge = calculateAge();
	calcAge.DOBYear <== date.year;
	calcAge.DOBMonth <== date.month;
	calcAge.DOBDay <== date.day;
	calcAge.CurYear <== currentYear;
	calcAge.CurMonth <== currentMonth;
	calcAge.CurDay <== currentDay;

    age <== calcAge.age;

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

    component gteY = GreaterEqThan(32);
    gteY.in[0] <== CurYear;
    gteY.in[1] <== DOBYear;
    gteY.out === 1;

    var yearDiff = CurYear - DOBYear;

    component ltM = LessThan(32);
    ltM.in[0] <== CurMonth * 100 + CurDay;
    ltM.in[1] <== DOBMonth * 100 + DOBDay;

    component gte0 = GreaterEqThan(32);
    gte0.in[0] <== yearDiff - ltM.out;
    gte0.in[1] <== 0;
    gte0.out === 1;

    age <== yearDiff - ltM.out;
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
