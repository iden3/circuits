import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

// inputs MUST be generated by GO-CIRCUITS library https://github.com/iden3/go-circuits (using corresponding test)
describe("idUtils.circom:", async function() {

    const tests = [
        {
            desc: "Salted hash",
            input: {
                in: "23630567111950550539435915649280822148510307443797111728722609533581131776", //379949150130214723420589610911161895495647789006649785264738141299135414272
                nonce: "10",
            },
            output: {
                out: "25425363284463910957419549722021124450832239517990785975889689633068548096",
            },
        },
    ];

    let circuit;
    this.timeout(300000)

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits", "idUtils_ProfileID.circom"),
            {
                output: path.join(__dirname, "../circuits", "build/idUtils_ProfileID"),
                recompile: true,
            },
        );
    });

    tests.forEach(({desc, input, output}) => {
        it(`ProfileID - ${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.checkConstraints(w);
            await circuit.assertOut(w, output);
        });
    });
});
