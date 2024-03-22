pragma circom 2.1.5;

include "../../../node_modules/circomlib/circuits/comparators.circom";

template ForceBabyCheckIfEnabled() {
    signal input {binary} enabled;
    signal input x;
    signal input y;

    signal x2;
    signal y2;

    var a = 168700;
    var d = 168696;

    x2 <== x*x;
    y2 <== y*y;

    ForceEqualIfEnabled()(enabled, [a*x2 + y2, 1 + d*x2*y2]);
}