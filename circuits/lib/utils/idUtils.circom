pragma circom 2.0.9;

include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/binsum.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template SaltID(){
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
    // fill 27 bytes state
    for (var i=0; i<256-24-16; i++) {
        checksum.in[i] <== stateBits.out[i+40];
    }
    // fill 2 bytes type
    for (var i=256-24-16; i<256-24; i++) {
            checksum.in[i] <== idBits.out[i-216];
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

    log("res.out", res.out);
    out <== res.out;
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
    log("sum:", sum);

    for (var i=0; i<16; i++) {
        out[i] <== sumBits.out[i];
    }

}

