import {expect} from "chai";
import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;

describe("Test linkedMultiQuery10.circom", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "../../circuits", "linkedMultiQuery10.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
            },
        );

    });

    after(async () => {
        circuit.release()
    })

    const basePath = '../../testvectorgen/credentials/linked/testdata/linked'
    const tests = [
        // sig
        require(`${basePath}/one_query.json`),
    ];

    tests.forEach(({ desc, inputs, expOut }) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

});
