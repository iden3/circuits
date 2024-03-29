import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const c_tester = require("circom_tester").c;
const chai = require("chai");
const assert = chai.assert;

export {};

const NOOP = "0"; // = - no operation, skip query verification if set
const EQUALS  = "1"; // = - equals sign
const LESS    = "2"; // = - less-than sign
const GREATER    = "3"; // = - greater-than sign
const IN = "4"; // = - in
const NOTIN = "5"; // = - notin
const NOTEQUALS = "6"; // = - not equals

describe("Test query",  function() {
    let circuit;

    before(async function() {
        this.timeout(60000)
        circuit = await wasm_tester(path.join(__dirname, "../circuits/query/", "queryTest.circom"));
    });

    describe("#Noop", function() {
        it("#Noop (true)", async () => {
            const inputs = {
                in: "10",
                operator:  NOOP,
                value: ["11", "0", "0"],
            }

            const expOut = {out: 1, value: ["11", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#Noop (true)", async () => {
            const inputs = {
                in: "0",
                operator:  NOOP,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 1, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

    describe("#IsEqual", function() {
        it("#IsEqual (false)", async () => {
            const inputs = {
                in: "10",
                operator:  EQUALS,
                value: ["11", "0", "0"],
            }

            const expOut = {out: 0, value: ["11", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IsEqual (true)", async () => {
            const inputs = {
                in: "10",
                operator:  EQUALS,
                value: ["10", "0", "0"],
            }

            const expOut = {out: 1, value: ["10", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IsEqual. Zero in. (false)", async () => {
            const inputs = {
                in: "0",
                operator:  EQUALS,
                value: ["11", "0", "0"],
            }

            const expOut = {out: 0, value: ["11", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IsEqual. Zero value. (false)", async () => {
            const inputs = {
                in: "10",
                operator:  EQUALS,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 0, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IsEqual. Zero both. (true)", async () => {
            const inputs = {
                in: "0",
                operator:  EQUALS,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 1, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

    });

    describe("#LessThan", function() {
        it("#LessThan - 10 < 11 (true)", async () => {
            const w = await circuit.calculateWitness({
                in: "10",
                operator: LESS,
                value: ["11", "0", "0"],
            }, true);

            const expOut = {out: 1, value: ["11", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan - 10 = 10 (false)", async () => {

            const w1 = await circuit.calculateWitness({
                in: "10",
                operator: LESS,
                value: ["10", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["10", "0", "0"]}

            await circuit.assertOut(w1, expOut);
            await circuit.checkConstraints(w1);
        });

        it("#LessThan - 10 < 9 (false)", async () => {
            const w2 = await circuit.calculateWitness({
                in: "10",
                operator:  LESS,
                value: ["9", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["9", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

        it("#LessThan - 0 < 11 (true)", async () => {
            const w = await circuit.calculateWitness({
                in: "0",
                operator: LESS,
                value: ["11", "0", "0"],
            }, true);

            const expOut = {out: 1, value: ["11", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan - 10 < 0 (false)", async () => {
            const w = await circuit.calculateWitness({
                in: "10",
                operator: LESS,
                value: ["0", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["0", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan - 0 < 0 (false)", async () => {
            const w = await circuit.calculateWitness({
                in: "0",
                operator: LESS,
                value: ["0", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["0", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan: p-1 < 10 should be false", async () => {
            const w = await circuit.calculateWitness({
                in: "-1",
                operator: LESS,
                value: ["10", "0", "0"],
            }, false);

            const expOut = {out: 0, value: ["10", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan: 10 < p-1 should be true", async () => {
            const w = await circuit.calculateWitness({
                in: "10",
                operator: LESS,
                value: ["-1", "0", "0"],
            }, false);

            const expOut = {out: 1, value: ["21888242871839275222246405745257275088548364400416034343698204186575808495616", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan: p-4294967290 < 10 should be false", async () => {
            const w = await circuit.calculateWitness({
                in: "-4294967290",
                operator: LESS,
                value: ["10", "0", "0"],
            }, false);

            const expOut = {out: 0, value: ["10", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan: p-345345345345345114294967290 < 10 should false", async () => {
            const w = await circuit.calculateWitness({
                in: "-345345345345345114294967290",
                // 1111111111111111111111111110011001100011011111010011010000000110
                // 111111101110001001010110010010000101000011100001100000100111000000101101001001000010010000000110
                operator: LESS,
                value: ["10", "0", "0"],
            }, false);

            const expOut = {out: 0, value: ["10", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#LessThan: 1465...3131 < 10 should be false", async () => {
            const w = await circuit.calculateWitness({
                in: "14651237294507013008273219182214280847718990358813499091232105186081237893131",
                operator: LESS,
                value: ["10", "0", "0"],
            }, false);

            const expOut = {out: 0, value: ["10", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

    describe("#GreaterThan", function() {
        it("#GreaterThan - 11 > 10 (true)", async () => {
            const w = await circuit.calculateWitness({
                in: "11",
                operator: GREATER,
                value: ["10", "0", "0"],
            }, true);

            const expOut = {out: 1, value: ["10", "0", "0"]}

            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#GreaterThan - 11 > 11 (false)", async () => {

            const w1 = await circuit.calculateWitness({
                in: "11",
                operator: GREATER,
                value: ["11", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["11", "0", "0"]}

            await circuit.assertOut(w1, expOut);
            await circuit.checkConstraints(w1);
        });

        it("#GreaterThan - 11 > 12 (false) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "11",
                operator:  GREATER,
                value: ["12", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["12", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

        it("#GreaterThan - 0 > 12 (false) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "0",
                operator:  GREATER,
                value: ["12", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["12", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

        it("#GreaterThan - 12 > 0 (true) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "12",
                operator:  GREATER,
                value: ["0", "0", "0"],
            }, true);

            const expOut = {out: 1, value: ["0", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

        it("#GreaterThan - 0 > 0 (false) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "0",
                operator:  GREATER,
                value: ["0", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["0", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

        it("#GreaterThan - p-1 > p-2 (true) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "-1",
                operator:  GREATER,
                value: ["-2", "0", "0"],
            }, true);

            const expOut = {out: 1, value: ["21888242871839275222246405745257275088548364400416034343698204186575808495615", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

        it("#GreaterThan - p-2 > p-1 (false) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "-2",
                operator:  GREATER,
                value: ["-1", "0", "0"],
            }, true);

            const expOut = {out: 0, value: ["21888242871839275222246405745257275088548364400416034343698204186575808495616", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

        it("#GreaterThan - p-1 > 0 (true) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "-1",
                operator:  GREATER,
                value: ["0", "0", "0"],
            }, true);

            const expOut = {out: 1, value: ["0", "0", "0"]}

            await circuit.assertOut(w2, expOut);
            await circuit.checkConstraints(w2);
        });

    });

    describe("#IN", function() {
        it("#IN 10 in ['12', '11', '10'] (true)", async () => {
            const inputs = {
                in: "10",
                operator:  IN,
                value: ["12", "11", "10"],
            }

            const expOut = {out: 1, value: ["12", "11", "10"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IN 11 in [`10`, `10`, `0`] (false)", async () => {
            const inputs = {
                in: "11",
                operator:  IN,
                value: ["10", "10", "0"],
            }

            const expOut = {out: 0, value: ["10", "10", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IN 0 in [`0`, `10`, `0`] (true)", async () => {
            const inputs = {
                in: "0",
                operator:  IN,
                value: ["0", "10", "0"],
            }

            const expOut = {out: 1, value: ["0", "10", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IN 0 IN [`10`, `11`, `12`] (false)", async () => {
            const inputs = {
                in: "0",
                operator:  IN,
                value: ["10", "11", "12"],
            }

            const expOut = {out: 0, value: ["10", "11", "12"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IN 11 in [`0`, `0`, `0`] (false)", async () => {
            const inputs = {
                in: "11",
                operator:  IN,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 0, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#IN 0 in [`0`, `0`, `0`] (true)", async () => {
            const inputs = {
                in: "0",
                operator:  IN,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 1, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

    });

    describe("#NOTIN", function() {
        it("#NOTIN 10 NOT in ['12', '11', '11'] (true)", async () => {
            const inputs = {
                in: "10",
                operator:  NOTIN,
                value: ["12", "11", "13"],
            }

            const expOut = {out: 1, value: ["12", "11", "13"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#NOTIN 10 NOT in [`10`, `10`, `0`] (false)", async () => {
            const inputs = {
                in: "10",
                operator:  NOTIN,
                value: ["10", "10", "0"],
            }

            const expOut = {out: 0, value: ["10", "10", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#NOTIN 0 NOT in [`10`, `10`, `10`] (true)", async () => {
            const inputs = {
                in: "0",
                operator:  NOTIN,
                value: ["10", "10", "10"],
            }

            const expOut = {out: 1, value: ["10", "10", "10"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#NOTIN 10 NOT in [`0`, `0`, `0`] (true)", async () => {
            const inputs = {
                in: "10",
                operator:  NOTIN,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 1, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("#NOTIN 0 NOT in [`0`, `0`, `0`] (false)", async () => {
            const inputs = {
                in: "0",
                operator:  NOTIN,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 0, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

    });

    describe("#NotEqual", function() {
        it("10 != 11 (true)", async () => {
            const inputs = {
                in: "10",
                operator: NOTEQUALS,
                value: ["11", "0", "0"],
            }

            const expOut = {out: 1, value: ["11", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("10 != 10 (false)", async () => {
            const inputs = {
                in: "10",
                operator: NOTEQUALS,
                value: ["10", "0", "0"],
            }

            const expOut = {out: 0, value: ["10", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("0 != 11 (true)", async () => {
            const inputs = {
                in: "0",
                operator: NOTEQUALS,
                value: ["11", "0", "0"],
            }

            const expOut = {out: 1, value: ["11", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("10 != 0 (true)", async () => {
            const inputs = {
                in: "10",
                operator: NOTEQUALS,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 1, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

        it("0 != 0 (false)", async () => {
            const inputs = {
                in: "0",
                operator: NOTEQUALS,
                value: ["0", "0", "0"],
            }

            const expOut = {out: 0, value: ["0", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });

    });

});
