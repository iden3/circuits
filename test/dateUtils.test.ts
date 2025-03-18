import {describe} from "mocha";
import {assert} from "chai";

const path = require("path");
const wasmTester = require("circom_tester").wasm;

describe("dateComparisonEncodedNormalized.circom", function() {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "./circuits/", "dateNormalize.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                include: [
                  path.join(__dirname, '../node_modules'),
                ],
            },
        );

    });

    after(async () => {
        circuit.release()
    })

    it(`Date is 19th centry`, async function() {
        const inputs = {
            date: "970401",
            currentDate: "250310",
        }
        const w = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(w);
        assert.equal(w[1], 19970401n);
    });
    it(`Date is 20th centry`, async function() {
        const inputs = {
            date: "020402",
            currentDate: "250310",
        }
        const w = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(w);
        assert.equal(w[1], 20020402n);
    });
});
