pragma circom 2.0.9;

include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/binsum.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template ProfileID(){
    signal input in;
    signal input salt;
    signal output out;

    // id bits
    component idBits = Num2Bits(256);
    idBits.in <== in;

    component hash = Poseidon(2);
    hash.inputs[0] <== in;
    hash.inputs[1] <== salt;

//    log("hash", hash.out);

    // hash bits
    component stateBits = Num2Bits(256);
    stateBits.in <== hash.out;

    // calculate checksum 29 (type[2],state[27])
    component checksum = CalculateChecksum(256-24); // 29 byte
    // fill 2 bytes type
    for (var i=256-24-16; i<256-24; i++) {
            checksum.in[i] <== idBits.out[i-216];
    }
    // fill 27 bytes state
    for (var i=0; i<256-24-16; i++) {
        checksum.in[i] <== stateBits.out[i+40];
    }


    component res = Bits2Num(256);

    // 2[0,1] bytes type
    for (var i=0; i<16; i++) {
       res.in[i] <== idBits.out[i];
    }

    // 27 [2-29] bytes state
    for (var i=16; i<256-24; i++) {
        res.in[i] <== stateBits.out[i-16+40];
    }


    // fill 2[30,31] bytes with checksum
    for (var i=256-24; i<256-16; i++) {
   // log("checksum", checksum.out[i-8]); //[1110 110001] //3633
        res.in[i] <== checksum.out[i-(256-24)+8];
    }
    for (var i=256-24; i<256-16; i++) {
        res.in[i+8] <== checksum.out[i-(256-24)];
    }

    // 32 byte empty
    for (var i=256-8; i<256; i++) {
        res.in[i] <== 0;
    }
    out <== res.out;
}

template ProfileID2(){
    signal input in;
    signal input salt;
    signal output out;

    component hash = Poseidon(2);
    hash.inputs[0] <== in;
    hash.inputs[1] <== salt;

    component genesis = TakeNBits(27*8);
    genesis.in <== hash.out;

    component oldIdParts = SplitID();
    oldIdParts.id <== in;

    component newId = NewID();
    newId.typ <== oldIdParts.typ;
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

// Shift in right by n bits
template ShiftRight(n) {
    signal input in;
    signal output out;
    // We take only most significant 27 * 8 bits from 254 bit number. 
    component bits = Num2Bits(254);
    bits.in <== in;

    component outBits = Bits2Num(254-n);
    for (var i = n; i < 254; i++) {
        outBits.in[i-n] <== bits.out[i];
    }
    out <== outBits.out;
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

template CalculateChecksum(n) {
    signal input in[n];
    signal output out[16];

    var sum = 0;

    for (var i=0; i<n; i=i+8){

        var lc1=0;
        var e2 = 1;
        for (var j = 0; j<8; j++) {
            lc1 += in[i+j] * e2;
            e2 = e2 + e2;
        }


        sum += lc1;
    }

    component sumBits = Num2Bits(16);
    sumBits.in <== sum;
//    log("sum:", sum);

    for (var i=0; i<16; i++) {
        out[i] <== sumBits.out[i];
    }

}

