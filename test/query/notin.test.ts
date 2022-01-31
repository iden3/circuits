import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe('Test NOTIN operator:', async function() {
    const tests = [
        {desc:'success',
            input: {
                in: "123",
                value: ["1234", "0", "9999"],
            },
            expOut: {}},
    ];

    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../../circuits/query/operators", "notinTest.circom"));
    });

    tests.forEach(({desc, input,expOut}) => {
        it(`${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
        });
    });
});
