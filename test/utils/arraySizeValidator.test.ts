import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test ArraySizeValidator template:", async function () {
    const tests = [
        {
            desc: "eq require 1 value array size input",
            input: {
                valueArraySize: "1",
                operator: "1",
            },
            expOut: { out: "1" }
        },
        {
            desc: "between require 2 value array size input",
            input: {
                valueArraySize: "2",
                operator: "9",
            },
            expOut: { out: "1" }
        },
        {
            desc: "in require less than 64 size input",
            input: {
                valueArraySize: "64",
                operator: "4",
            },
            expOut: { out: "1" }
        },
        {
            desc: "nin more than 64 size input",
            input: {
                valueArraySize: "65",
                operator: "5",
            },
            expOut: { out: "0" }
        },
        {
            desc: "sd with 1 value arr size",
            input: {
                valueArraySize: "1",
                operator: "16",
            },
            expOut: { out: "0" }
        },
        {
            desc: "sd with 0 value arr size",
            input: {
                valueArraySize: "0",
                operator: "16",
            },
            expOut: { out: "1" }
        },
        {
            desc: "gte with 2 value arr size",
            input: {
                valueArraySize: "2",
                operator: "8",
            },
            expOut: { out: "0" }
        },
    ];

    let circuit;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/utils/", "utils_arraySizeValidatorTest.circom"));
    });

    tests.forEach(({ desc, input, expOut }) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });
});
