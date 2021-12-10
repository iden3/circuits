import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe('Test getClaimExpiration:', async function() {
    const tests = [
        {desc:'success',
         input: {claim:["2722258935367507707706996859454145691697",
                "0",
                "0",
                "0",
                "30803922974473213664682835967", // expiration 1669884010
                "0",
                "0",
                "0"],},
         expOut: {expiration:1669884010}},

        {
            desc: 'expiration 0 revocation 0',
            input: {claim:["2722258935367507707706996859454145691697",
                    "0",
                    "0",
                    "0",
                    "0", // revocation 0 && expiration 0
                    "0",
                    "0",
                    "0"]},
            expOut: {expiration: 0}
        },

        {
            desc: "expiration max revocation 0",
            input: {
                claim: ["2722258935367507707706996859454145691697",
                    "0",
                    "0",
                    "0",
                    "170141183460469231713240559642174554112", // revocation 0 && expiration MAX
                    "0",
                    "0",
                    "0"]
            },
            expOut: {expiration: 9223372036854775807}
        },

        {
            desc: 'expiration max & revocation max',
            input: {
                claim: ["2722258935367507707706996859454145691697",
                    "0",
                    "0",
                    "0",
                    "170141183460469231731687303715884105727", // revocation MAX && expiration MAX
                    "0",
                    "0",
                    "0"]
            },
            expOut: {expiration: 9223372036854775807}
        }


    ];

    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/credential", "credential_getClaimExpiration.circom"));
    });

    tests.forEach(({desc, input,expOut}) => {
        it(`getClaimExpiration ${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
        });
    });
});
