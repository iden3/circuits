pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/mux2.circom";
include "./idUtils.circom";
include "./babyjubjub.circom";

// getClaimSubjectOtherIden checks that a claim Subject is OtherIden and outputs the identity within.
template getClaimSubjectOtherIden() {
    signal input claim[8];
    signal input {binary} claimFlags[32];
    signal output id;

    // get subject location from header flags.
    component subjectLocation = getSubjectLocation();
    subjectLocation.claimFlags <== claimFlags;

    component mux = Mux3();
    component n2b = Num2Bits(3);
    n2b.in <== subjectLocation.out;

    mux.s <== n2b.out;

    mux.c[0] <== 0;
    mux.c[1] <== 0;
    mux.c[2] <== claim[0*4 + 1];
    mux.c[3] <== claim[1*4 + 1];
    mux.c[4] <== 0;
    mux.c[5] <== 0;
    mux.c[6] <== 0;
    mux.c[7] <== 0;

    id <== mux.out;

    // explicitly state that these signals are not used and it's ok
    for (var i=0; i<8; i++) {
        _ <== claim[i];
    }
}

// getClaimMerkilizeFlag checks that a claim flag is set and return merklized slot.
template getClaimMerklizeRoot() {
    signal input claim[8];
    signal input {binary} claimFlags[32];
    signal output {binary} flag; // 0 non merklized, 1 merklized

    // merklizeFlag = 0 out = 0 , non merkilized
    // merklizeFlag = 1 out=claim_i_2, root is stored in index slot 2 (i_2)
    // merklizeFlag = 2 out=claim_v_2, root is stored in value slot 2 (v_2)
    signal output out;

    // get subject location from header flags.
    signal merklizeLocation <== getMerklizeLocation()(claimFlags);

    component mux = Mux3();
    component n2b = Num2Bits(3);
    n2b.in <== merklizeLocation;

    mux.s <== n2b.out;

    mux.c[0] <== 0;
    mux.c[1] <== claim[0*4 +2];
    mux.c[2] <== claim[1*4 +2];
    mux.c[3] <== 0;
    mux.c[4] <== 0;
    mux.c[5] <== 0;
    mux.c[6] <== 0;
    mux.c[7] <== 0;

    out <== mux.out;

    flag <== GreaterThan(3)([merklizeLocation, 0]); // there's only 3 bits in merklizeLocation

    // explicitly state that some signals are not used and it's ok
    for (var i=0; i<8; i++) {
        _ <== claim[i];
    }
}


// getClaimHeader gets the header of a claim, outputting the claimType as an
// integer and the claimFlags as a bit array.
template getClaimHeader() {
    signal input claim[8];

    signal output schema;
    signal output {binary} claimFlags[32];

    component i0Bits = Num2Bits_strict();
    i0Bits.in <== claim[0];

    component schemaNum = Bits2Num(128);

    for (var i=0; i<128; i++) {
        schemaNum.in[i] <== i0Bits.out[i];
    }
    schema <== schemaNum.out;

    for (var i=0; i<32; i++) {
        claimFlags[i] <== i0Bits.out[128 + i];
    }

    // explicitly state that some of these signals are not used and it's ok
    for (var i=1; i<8; i++) {
        _ <== claim[i];
    }
    for (var i=160; i<254; i++) {
        _ <== i0Bits.out[i];
    }
}

// getClaimRevNonce gets the revocation nonce out of a claim outputing it as an integer.
template getClaimRevNonce() {
    signal input claim[8];

    signal output revNonce;

    component claimRevNonce = Bits2Num(64);

    component v0Bits = Num2Bits_strict();
    v0Bits.in <== claim[4];
    for (var i=0; i<64; i++) {
        claimRevNonce.in[i] <== v0Bits.out[i];
    }
    revNonce <== claimRevNonce.out;

    // explicitly state that some of these signals are not used and it's ok
    for (var i=0; i<8; i++) {
        _ <== claim[i];
    }
    for (var i=0; i<254; i++) {
        _ <== v0Bits.out[i];
    }
}

//  getClaimHiHv calculates the hashes Hi and Hv of a claim (to be used as
//  key,value in an SMT).
template getClaimHiHv() {
    signal input claim[8];

    signal output hi;
    signal output hv;

    component hashHi = Poseidon(4);
    for (var i=0; i<4; i++) {
        hashHi.inputs[i] <== claim[i];
    }
    hi <== hashHi.out;

    component hashHv = Poseidon(4);
    for (var i=0; i<4; i++) {
        hashHv.inputs[i] <== claim[4 + i];
    }
    hv <== hashHv.out;
}

//  getClaimHash calculates the hash a claim
template getClaimHash() {
    signal input claim[8];
    signal output hash;
    signal output hi;
    signal output hv;

    (hi, hv) <== getClaimHiHv()(claim);

    hash <== Poseidon(2)([hi, hv]);
}

// verifyCredentialSubject verifies that claim is issued to a specified identity or identity profile
// if nonce 0 is used, the claim should be issued to the genesis identity
template verifyCredentialSubjectProfile() {
    signal input {binary} enabled;
    signal input claim[8];
    signal input {binary} claimFlags[32];
    signal input id;
    signal input nonce;

    signal subjectOtherIdenId <== getClaimSubjectOtherIden()(claim, claimFlags);

    /* ProfileID calculation */
    component profile = SelectProfile();
    profile.in <== id;
    profile.nonce <== nonce;

    ForceEqualIfEnabled()(
        enabled,
        [subjectOtherIdenId, profile.out]
    );
}

// verifyCredentialSchema verifies that claim matches provided schema
template verifyCredentialSchema() {
    signal input {binary} enabled;
    signal input claimSchema;
    signal input schema;

    ForceEqualIfEnabled()(
        enabled,
        [claimSchema, schema]
    );
}

// verifyClaimSignature verifies that claim is signed with the provided public key
template verifyClaimSignature() {
    signal input {binary} enabled;
    signal input claimHash;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input pubKeyX;
    signal input pubKeyY;

    ForceBabyCheckIfEnabled()(enabled, sigR8x, sigR8y);

    // signature verification
    EdDSAPoseidonVerifier()(
        enabled <== enabled,
        Ax <== pubKeyX,
        Ay <== pubKeyY,
        S <== sigS,
        R8x <== sigR8x,
        R8y <== sigR8y,
        M <== claimHash
    );
}

template checkDataSignatureWithPubKeyInClaim() {
    signal input {binary} enabled;
    signal input claim[8];
    signal input signatureS;
    signal input signatureR8X;
    signal input signatureR8Y;
    signal input data;

    component getPubKey = getPubKeyFromClaim();
    getPubKey.claim <== claim;

    ForceBabyCheckIfEnabled()(enabled, signatureR8X, signatureR8Y);

    EdDSAPoseidonVerifier()(
        enabled <== enabled,
        Ax <== getPubKey.Ax,
        Ay <== getPubKey.Ay,
        S <== signatureS,
        R8x <== signatureR8X,
        R8y <== signatureR8Y,
        M <== data
    );
}

template getPubKeyFromClaim() {
    signal input claim[8];
    signal output Ax;
    signal output Ay;

    Ax <== claim[2]; // Ax should be in indexSlotA
    Ay <== claim[3]; // Ay should be in indexSlotB

    // explicitly state that these signals are not used and it's ok
    for (var i=0; i<8; i++) {
        _ <== claim[i];
    }
}

// getValueByIndex select slot from claim by given index
template getValueByIndex(){
    signal input claim[8];
    signal input index;
    signal output value; // value from the selected slot claim[index]

    component mux = Mux3();
    component n2b = Num2Bits(3);
    n2b.in <== index;
    for(var i=0;i<8;i++){
        mux.c[i] <== claim[i];
    }

    mux.s[0] <== n2b.out[0];
    mux.s[1] <== n2b.out[1];
    mux.s[2] <== n2b.out[2];

    value <== mux.out;
}

// verify that provided timestamp is less than claim expiration time
template verifyExpirationTime() {
    signal input {binary} expirationFlag; // claimFlags[3] (expiration flag) is set
    signal input claim[8];
    signal input timestamp;

    _ <== Num2Bits(64)(timestamp); // allow max 64 bit number for timestamp

    signal claimExpiration <== getClaimExpiration()(claim);

    // timestamp < claimExpiration
    signal lt <== LessEqThan(64)([
        timestamp,
        claimExpiration]
    );

    ForceEqualIfEnabled()(
        expirationFlag,
        [lt, 1]
    );
}

// getClaimExpiration extract expiration date from claim
template getClaimExpiration() {
    signal input claim[8];

    signal output {maxbit} expiration;

    component expirationBits = Bits2Num(64);

    component v0Bits = Num2Bits_strict();
    v0Bits.in <== claim[4];
    for (var i=0; i<64; i++) {
        expirationBits.in[i] <== v0Bits.out[i+64];
    }
    expiration.maxbit = 64;
    expiration <== expirationBits.out;

    // explicitly state that some of these signals are not used and it's ok
    for (var i=0; i<8; i++) {
        _ <== claim[i];
    }
    for (var i=0; i<254; i++) {
        _ <== v0Bits.out[i];
    }
}

// getSubjectLocation extract subject from claim flags.
template getSubjectLocation() {
    signal input {binary} claimFlags[32];
    signal output out;

    component subjectBits = Bits2Num(3);

    for (var i=0; i<3; i++) {
        subjectBits.in[i] <== claimFlags[i];
    }

    out <== subjectBits.out;

    // explicitly state that some of these signals are not used and it's ok
    for (var i=0; i<32; i++) {
        _ <== claimFlags[i];
    }
}

// getMerklizeLocation extract merklize from claim flags.
// 0 - not merklized, 1 - root in index slot i_2[root], 2 - root in value slot v_2[root]
template getMerklizeLocation() {
    signal input {binary} claimFlags[32];
    signal output out;

    component mtBits = Bits2Num(3);

    for (var i=5; i<8; i++) {
        mtBits.in[i-5] <== claimFlags[i];
    }

    out <== mtBits.out;

    // explicitly state that some of these signals are not used and it's ok
    for (var i=0; i<32; i++) {
        _ <== claimFlags[i];
    }
}

// isExpirable return 1 if expiration flag is set otherwise 0.
template isExpirable() {
        signal input {binary} claimFlags[32];
        signal output out;

        out <== claimFlags[3];
}

// isUpdatable return 1 if updatable flag is set otherwise 0.
template isUpdatable() {
        signal input {binary} claimFlags[32];
        signal output {binary} out;

        out <== claimFlags[4];
}
