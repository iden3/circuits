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

    // component genesis = TakeGenesis();
    // genesis.in <== hash.out;

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

    component genesis = TakeGenesis();
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

    component bs = Num2Bits(253);
    bs.in <== id;

    // checksum bytes are swapped in ID. 31-th byte is first and 30-th is second.
    component checksumBits = Bits2Num(16);
    for (var i = 0; i < 8; i++) {
        checksumBits.in[i] <== bs.out[30 * 8 + i];
    }
    for (var i = 8; i < 16; i++) {
        checksumBits.in[i] <== bs.out[29 * 8 + i - 8];
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

    component s = CalculateChecksum2();
    s.typ <== typ;
    s.genesis <== genesis;

    // put checksum to 30, 31 bytes
    var id = (s.out & 0xff) << (30 * 8);
    id += (s.out & 0xff00) << (28 * 8);
    // put genesis to 2-29 bytes
    id += (genesis & (2 ** (27 * 8) - 1)) << (2 * 8);
    // put id type
    id += typ & (2 ** (2 * 8) - 1);
    out <-- id;
}

// return 31-byte ID made up from type, genesis and checksum
template GatherID() {
    signal input typ;
    signal input genesis;
    signal input checksum;
    signal output out;

    // assert checksum is correct
    component s = CalculateChecksum2();
    s.typ <== typ;
    s.genesis <== genesis;
    s.out === checksum;

    // put checksum to 30, 31 bytes
    var id = (checksum & 0xff) << (30 * 8);
    id += (checksum & 0xff00) << (28 * 8);
    // put genesis to 2-29 bytes
    id += (genesis & (2 ** (27 * 8) - 1)) << (2 * 8);
    // put id type
    id += typ & (2 ** (2 * 8) - 1);
    out <-- id;
}

// take 27-byte genesis from 32-byte int
template TakeGenesis() {
    signal input in;
    signal output out;
    // We take only most significant 27 * 8 bits from 256 bit number. 
    // So we strip remaining 40 least significan bits.
    out <-- in >> 40;

    // create constraint
    component res = Num2Bits(256);
    res.in <== in;
    var e2 = 1;
    var lc1 = 0;
    for (var i = 40; i < 256; i++) {
        lc1 += res.out[i] * e2;
        e2 = e2 + e2;
    }
    lc1 === out;
}

// return uint16 checksum
template CalculateChecksum2() {
    signal input typ;
    signal input genesis;
    signal output out;

    var acc = 0;
    var val = typ;
    component sumTyp = SumModulus(8, 16);
    sumTyp.in <== typ;
    sumTyp.start <== 0;

    component sumGen = SumModulus(8, 16);
    sumGen.in <== genesis;
    sumGen.start <== sumTyp.out;

    out <== sumGen.out;
}

// split input into bits of dim size and sum number by modulus 2**mod
// for example, to split input into bytes (8 bits) and create sum modulus 16 bytes,
// create template as SumModulus(8, 16)
template SumModulus(dim, mod) {
    signal input start; 
    signal input in;
    signal output out;

    var val = in;
    var acc = start;
    while (val > 0) {
        // log("[1] ", acc, " ", val & (2 ** dim - 1), " ", val);
        acc = acc + (val & (2 ** dim - 1));
        acc = acc % (2 ** mod - 1);
        val = val >> dim;
    }

    out <-- acc;
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

