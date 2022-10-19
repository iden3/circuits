import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

// inputs MUST be generated by GO-CIRCUITS library https://github.com/iden3/go-circuits (using corresponding test)
describe("idUtils.circom:", async function() {
    
    const tests = [
        {
            desc: "First",
            input: {
                id: "376456579615209717367026420083895536778545545416798606485883050226426692080",
            },
            output: {
                typ: "49648",
                genesis: "12590477270745565760216918871818154904274440992307045641577748017",
                checksum: "4565",
            },
        },
    ];

    let circuit;
    this.timeout(300000)

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits", "idUtils_SplitID.circom"),
            {
                output: path.join(__dirname, "../circuits", "build/idUtils_SplitID"),
                recompile: true,
                reduceConstraints: true,
            },
        );
    });

    tests.forEach(({desc, input, output}) => {
        it(`auth ${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.checkConstraints(w);
            await circuit.assertOut(w, output);
        });
    });
});
