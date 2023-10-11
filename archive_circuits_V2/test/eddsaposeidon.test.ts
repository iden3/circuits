const path = require("path");
const tester = require("circom_tester").wasm;
const buildEddsa = require("circomlibjs").buildEddsa;
const buildBabyjub = require("circomlibjs").buildBabyjub;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("EdDSA Poseidon test", function () {
    this.timeout(200000);
    let circuit;
    let eddsa;
    let babyJub;
    let F;

    before(async function() {
        eddsa = await buildEddsa();
        babyJub = await buildBabyjub();
        F = babyJub.F;

        circuit = await tester(path.join(__dirname, "circuits", "eddsaposeidon.circom"));
    });

    it("Sign a single number", async () => {

        const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
        const pubKey = eddsa.prv2pub(prvKey);

        for (var i=0; i<100; i++) {

            const msg = F.e(Math.round(Math.random() * 1e10));
            const signature = eddsa.signPoseidon(prvKey, msg);

            assert(eddsa.verifyPoseidon(msg, signature, pubKey));

            const input = {
                enabled: 1,
                Ax: F.toObject(pubKey[0]),
                Ay: F.toObject(pubKey[1]),
                R8x: F.toObject(signature.R8[0]),
                R8y: F.toObject(signature.R8[1]),
                S: signature.S,
                M: F.toObject(msg)
            };

            // console.log(JSON.stringify(utils.stringifyBigInts(input)));

            const w = await circuit.calculateWitness(input, true);

            await circuit.checkConstraints(w);
        }
    });

});

