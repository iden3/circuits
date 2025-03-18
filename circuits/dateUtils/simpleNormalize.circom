pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

// This circuit converts a date in YYMMDD format to YYYYMMDD format
// using a simple comparison with currentDate to determine the century
template DateFormatConverter() {
    // Input signals
    signal input date;
    signal input currentDate;

    // Output signal
    signal output formattedDate; // Date in format YYYYMMDD
    
    component dateCompare = LessThan(48);
    dateCompare.in[0] <== date;
    dateCompare.in[1] <== currentDate;
    signal dateLessOrEqual <== dateCompare.out;
    
    signal centuryPrefix;
    centuryPrefix <== 20000000 * dateLessOrEqual + 19000000 * (1 - dateLessOrEqual);
     
    formattedDate <== centuryPrefix + date;
}