pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

/////////////////////////////////////////////////////////////////
// SafeZeroOne calculates safe one signals from any signal coming from outside of circuit
// It is needed because linear constraints are not giving real security guarantees and circom is
// removing them during optimization pass.
// Because of this `===` without multiplications gives 0 constraints!!!
// ForceEqualIfEnabled(1, [x, y]) gives 0 too.
// Only ForceEqualIfEnabled(enabled, [x, y]) with `enabled` from input signal or signal safely derived
// from input signal generates constraints.
// That's why we need to calculate safe zero and one signals from input signal.
/////////////////////////////////////////////////////////////////
template SafeOne() {
    signal input inputSignal;
    signal tmp <== IsZero()(inputSignal);
    signal tmp2 <== NOT()(tmp);
    signal zero <== IsEqual()([tmp, tmp2]);
    signal output {binary} one <== IsZero()(zero);
    zero * one === 0;
}
