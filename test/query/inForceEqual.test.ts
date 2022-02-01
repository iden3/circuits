import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test IN operator:", async function() {
    const tests = [
        {desc: "single accepted value",
            input: {
                in: "123",
                value: ["123", "9999"],
            },
            expOut: {}},

        {desc: "multiple accepted values",
            input: {
                in: "123",
                value: ["123", "123", "999"],
            },
            expOut: {}},
        {desc: "all accepted values",
            input: {
                in: "123",
                value: ["123", "123", "123"],
            },
            expOut: {}},
    ];

    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/query/", "inForceEqualTest.circom"));
    });

    tests.forEach(({desc, input, expOut}) => {
        it(`${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
        });
    });
});
