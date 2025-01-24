import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;

// export {};

describe("Test stateTransition.circom", function() {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "../circuits/", "stateTransitionV3.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
            },
        );

    });

    after(async () => {
        circuit.release()
    })

    const basePath = '../testvectorgen/statetransition/testdata'
    const tests = [
        require(`${basePath}/genesis_state.json`),
        require(`${basePath}/not_genesis_state.json`),
    ];

    tests.forEach(({desc, inputs, expOut}) => {
        it(`${desc}`, async function() {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

});
