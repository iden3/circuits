import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test getClaimHeader:", async function() {
    const tests = [
        {
            desc: "Test claim header",
            inputs: {claim: ["10889035741470030830827987437816582766592", "0", "999", "0", "0", "0", "0", "0"]},
            expOut: {schema: 0, claimFlags: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
        },
        {
            desc: "Test claim header",
            inputs: {claim: ["21778071482940061661655974875633165533184", "0", "999", "888", "0", "0", "777", "666"]},
            expOut: {schema: 0, claimFlags: [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
        },
    ];

    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/utils", "claimUtils_getClaimHeader.circom"));
    });

    tests.forEach(({desc, inputs, expOut}) => {
        it(`getClaimHeader ${desc}`, async function() {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
        });
    });
});
