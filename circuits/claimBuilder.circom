pragma circom 2.1.9;

include "circomlib/circuits/smt/smtprocessor.circom";

template ClaimRootBuilder(nLevels, smtChanges) {
    signal input templateRoot;
    signal input siblings[smtChanges][nLevels];
    signal input keys[smtChanges];
    signal input values[smtChanges];

    signal output newRoot;

    signal intermediate[smtChanges+1];
    intermediate[0] <== templateRoot;
    
    component smt[smtChanges];
    for(var i = 0; i < smtChanges; i++){
        smt[i] = SMTProcessor(nLevels);
        smt[i].oldRoot <== intermediate[i];
        smt[i].siblings <== siblings[i];
        smt[i].oldKey <== keys[i];
        smt[i].oldValue <== 0;
        smt[i].isOld0 <== 0;
        smt[i].newKey <== keys[i];
        smt[i].newValue <== values[i];
        smt[i].fnc <== [0, 1];
        intermediate[i+1] <== smt[i].newRoot;
    }

    // return latest tree root
    newRoot <== smt[smtChanges-1].newRoot;
}
