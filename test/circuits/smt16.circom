pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/gates.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";
include "../../node_modules/circomlib/circuits/smt/smtlevins.circom";
include "../../node_modules/circomlib/circuits/smt/smtverifiersm.circom";
include "../../node_modules/circomlib/circuits/smt/smthash_poseidon.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

template SMTVerifierLevel16() {
    signal input st_top;
    signal input st_i0;
    signal input st_iold;
    signal input st_inew;
    signal input st_na;

    signal output root;
    signal input siblings[16];
    signal input old1leaf;
    signal input new1leaf;
    signal input lrbit;
    signal input child;

    signal aux[2];

    component proofHash = Poseidon(16);

    for (var i=0; i<16; i++) {
        proofHash.inputs[i] <== siblings[i];
    }

    aux[0] <== proofHash.out * st_top;
    aux[1] <== old1leaf*st_iold;

    root <== aux[0] + aux[1] + new1leaf*st_inew;
}

template SMTVerifier(nLevels) {
    signal input enabled;
    signal input root;
    signal input siblings[16*nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;
    signal input key;
    signal input value;
    signal input fnc;

    var i;

    component hash1Old = SMTHash1();
    hash1Old.key <== oldKey;
    hash1Old.value <== oldValue;

    component hash1New = SMTHash1();
    hash1New.key <== key;
    hash1New.value <== value;

    component n2bOld = Num2Bits_strict();
    component n2bNew = Num2Bits_strict();

    n2bOld.in <== oldKey;
    n2bNew.in <== key;

    component smtLevIns = SMTLevIns(nLevels);
    for (i=0; i<nLevels; i++) smtLevIns.siblings[i] <== siblings[i];
    smtLevIns.enabled <== enabled;

    component sm[nLevels];
    for (i=0; i<nLevels; i++) {
        sm[i] = SMTVerifierSM();
        if (i==0) {
            sm[i].prev_top <== enabled;
            sm[i].prev_i0 <== 0;
            sm[i].prev_inew <== 0;
            sm[i].prev_iold <== 0;
            sm[i].prev_na <== 1-enabled;
        } else {
            sm[i].prev_top <== sm[i-1].st_top;
            sm[i].prev_i0 <== sm[i-1].st_i0;
            sm[i].prev_inew <== sm[i-1].st_inew;
            sm[i].prev_iold <== sm[i-1].st_iold;
            sm[i].prev_na <== sm[i-1].st_na;
        }
        sm[i].is0 <== isOld0;
        sm[i].fnc <== fnc;
        sm[i].levIns <== smtLevIns.levIns[i];
    }
    sm[nLevels-1].st_na + sm[nLevels-1].st_iold + sm[nLevels-1].st_inew + sm[nLevels-1].st_i0 === 1;

    component levels[nLevels];
    for (i=nLevels-1; i != -1; i--) {
        levels[i] = SMTVerifierLevel16();

        levels[i].st_top <== sm[i].st_top;
        levels[i].st_i0 <== sm[i].st_i0;
        levels[i].st_inew <== sm[i].st_inew;
        levels[i].st_iold <== sm[i].st_iold;
        levels[i].st_na <== sm[i].st_na;

        for (var j=0; j<16; j++) {
            levels[i].siblings[j] <== siblings[i*16+j];
        }
        levels[i].old1leaf <== hash1Old.out;
        levels[i].new1leaf <== hash1New.out;

        levels[i].lrbit <== n2bNew.out[i];
        if (i==nLevels-1) {
            levels[i].child <== 0;
        } else {
            levels[i].child <== levels[i+1].root;
        }
    }


    // Check that if checking for non inclussuin and isOld0==0 then key!=old
    component areKeyEquals = IsEqual();
    areKeyEquals.in[0] <== oldKey;
    areKeyEquals.in[1] <== key;

    component keysOk = MultiAND(4);
    keysOk.in[0] <== fnc;
    keysOk.in[1] <== 1-isOld0;
    keysOk.in[2] <== areKeyEquals.out;
    keysOk.in[3] <== enabled;

    keysOk.out === 0;

    // Check the root
    component checkRoot = ForceEqualIfEnabled();
    checkRoot.enabled <== enabled;
    checkRoot.in[0] <== levels[0].root;
    checkRoot.in[1] <== root;

    // levels[0].root === root;

}

component main = SMTVerifier(10);
