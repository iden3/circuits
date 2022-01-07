pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";

template getDateFromTimestamp(){
	signal input timestamp;
    signal output year;
    signal output month;
    signal output day;


    signal z;
    signal era;
    signal erac;

    signal doe;
    signal yoem;
    signal yoe;
    signal y;

	z <--  (timestamp - timestamp % 86400 )/86400 + 719468;
   	era <-- z > 0 ? z : z - 146096;
    erac <-- (era - era % 146096) / 146096;
	doe <-- z - erac * 146097;

    yoem <-- doe - ( doe - doe % 1460) / 1460 + ( doe - doe % 36524) / 36524 - ( doe - doe % 146096) / 146096;
    yoe  <-- (yoem - yoem % 365) / 365;
    y <-- yoe + erac * 400;


    signal doy;
    signal mpm;
    signal mp;
	doy <-- doe - (365*yoe + (yoe - yoe % 4 )/ 4  - (yoe - yoe % 100 )/ 100);
	mpm <-- 5*doy + 2;
	mp  <-- (mpm - mpm % 153) / 153;

    signal dm;
    signal m;
    signal d;

    dm <-- 153*mp+2;
	d  <--  doy - (dm - dm % 5) / 5 + 1;
    m  <-- mp < 10 ? mp + 3 : mp -9 ;

    signal yy;

    yy <-- m <=2 ? y + 1 : y;

    year <== yy;
    month <== m;
    day <== d;
}

template getDateFromYYYYMMDD(){
	signal input yyyymmdd;
    signal output year;
    signal output month;
    signal output day;

    signal mmdd;
    signal yyyy;
    signal mm;
    signal dd;

    mmdd <-- yyyymmdd % 10000;
    yyyy <-- (yyyymmdd - mmdd) / 10000;
    dd <-- mmdd % 100;
    mm <-- (mmdd - dd) / 100;

    year <== yyyy;
    month <== mm;
    day <== dd;
}

