pragma circom 2.0.9;

include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/binsum.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";

template ProfileID(){
    signal input in;
    signal input nonce;
    signal output out;

    component hash = Poseidon(2);
    hash.inputs[0] <== in;
    hash.inputs[1] <== nonce;

    component genesis = TakeNBits(27*8);
    genesis.in <== hash.out;

    component genesisIdParts = SplitID();
    genesisIdParts.id <== in;

    component newId = NewID();
    newId.typ <== genesisIdParts.typ;
    newId.genesis <== genesis.out;

    out <== newId.out;
}

// Split ID into type, genesys and checksum
template SplitID() {
    signal input id;
    signal output typ;
    signal output genesis;
    signal output checksum;

    component bs = Num2Bits(254);
    bs.in <== id;

    // checksum bytes are swapped in ID. 31-th byte is first and 30-th is second.
    component checksumBits = Bits2Num(16);
    for (var i = 0; i < 16; i++) {
        checksumBits.in[i] <== bs.out[29 * 8 + i];
    }
    checksum <== checksumBits.out;

    component genesisBits = Bits2Num(216);
    for (var i = 0; i < 216; i++) {
        genesisBits.in[i] <== bs.out[i + 16];
    }
    genesis <== genesisBits.out;

    component typBits = Bits2Num(16);
    for (var i = 0; i < 16; i++) {
        typBits.in[i] <== bs.out[i];
    }
    typ <== typBits.out;
}

template NewID() {
    signal input typ;
    signal input genesis;
    signal output out;

    component s = CalculateIdChecksum();
    s.typ <== typ;
    s.genesis <== genesis;

    component id = GatherID();
    id.typ <== typ;
    id.genesis <== genesis;
    id.checksum <== s.out;

    out <== id.out;
}

// return 31-byte ID made up from type, genesis and checksum
template GatherID() {
    signal input typ;
    signal input genesis;
    signal input checksum;
    signal output out;

    component idBits = Bits2Num(31*8);

    component checksumBits = Num2Bits(2*8);
    checksumBits.in <== checksum;
    for (var i = 0; i < 16; i++) {
        idBits.in[29*8+i] <== checksumBits.out[i];
    }

    component genesisBits = Num2Bits(27*8);
    genesisBits.in <== genesis;
    for (var i = 0; i < 27 * 8; i++) {
        idBits.in[2*8+i] <== genesisBits.out[i];
    }

    component typBits = Num2Bits(2*8);
    typBits.in <== typ;
    for (var i = 0; i < 2 * 8; i++) {
        idBits.in[i] <== typBits.out[i];
    }

    out <== idBits.out;
}

// Take least significan n bits
template TakeNBits(n) {
    signal input in;
    signal output out;
    // We take only least significant 27 * 8 bits from 254 bit number. 
    component bits = Num2Bits(254);
    bits.in <== in;

    component outBits = Bits2Num(n);
    for (var i = 0; i < n; i++) {
        outBits.in[i] <== bits.out[i];
    }
    out <== outBits.out;
}

template CalculateIdChecksum() {
    signal input typ;
    signal input genesis;
    signal output out;

    var sum = 0;

    component typBits = Num2Bits(256);
    typBits.in <== typ;
    for (var i = 0; i < 256; i = i + 8) {
        var lc1 = 0;
        var e2 = 1;
        for (var j = 0; j < 8; j++) {
            lc1 += typBits.out[i + j] * e2;
            e2 = e2 + e2;
        }
        sum += lc1;
    }

    component genesisBits = Num2Bits(256);
    genesisBits.in <== genesis;
    for (var i = 0; i < 256; i = i + 8) {
        var lc1 = 0;
        var e2 = 1;
        for (var j = 0; j < 8; j++) {
            lc1 += genesisBits.out[i + j] * e2;
            e2 = e2 + e2;
        }
        sum += lc1;
    }

    component sumBits = LastNBits(16);
    sumBits.in <== sum;
    out <== sumBits.out;
}

template LastNBits(n) {
    signal input in;
    signal output out;

    component inBits = Num2Bits(254);
    inBits.in <== in;

    component outBits = Bits2Num(n);
    for (var i = 0; i < n; i++) {
        outBits.in[i] <== inBits.out[i];
    }
    out <== outBits.out;
}

// SelectProfile `out` output signal will be assigned with user profile,
// unless nonce == 0, in which case profile will be assigned with `in` id
template SelectProfile() {
    signal input in;
    signal input nonce;

    signal output out;

    component calcProfile = ProfileID();
    calcProfile.in <== in;
    calcProfile.nonce <== nonce;

    component isSaltZero = IsZero();
    isSaltZero.in <== nonce;

    component selectProfile = Mux1();
    selectProfile.s <== isSaltZero.out;
    selectProfile.c[0] <== calcProfile.out;
    selectProfile.c[1] <== in;

    out <== selectProfile.out;
}
