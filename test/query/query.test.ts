import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

const EQUALS  = "0"; // = - equals sign
const LESS    = "1"; // = - less-than sign
const GREATER    = "2"; // = - greter-than sign
const IN = "3"; // = - in
const NOTIN = "4"; // = - notin

describe("Test query",  function() {
    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/query/", "queryTest.circom"));
    });

    describe("#IsEqual", function() {
        it("#IsEqual - false", async () => {
            const inputs = {
                in: "10",
                operator:  EQUALS,
                value: ["11", "0", "0"],
            }

            const expOut = {out: 0, value: ["11", "0", "0"]}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
        });

        it("#IsEqual - true", async () => {
            const inputs = {
                in: "10",
                operator:  EQUALS,
                value: ["10", "0", "0"],
            }

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, {out: 1});

        });

    });

    describe("#LessThan", function() {
        it("#LessThan - 10 < 11", async () => {
            const w = await circuit.calculateWitness({
                in: "10",
                operator: LESS,
                value: ["11", "0", "0"],
            }, true);

            await circuit.assertOut(w, {out: 1});
        });

        it("#LessThan - 10 = 10", async () => {

            const w1 = await circuit.calculateWitness({
                in: "10",
                operator: LESS,
                value: ["10", "0", "0"],
            }, true);

            await circuit.assertOut(w1, {out: 0});
        });

        it("#LessThan - 10 < 9 ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "10",
                operator:  LESS,
                value: ["9", "0", "0"],
            }, true);

            await circuit.assertOut(w2, {out: 0});
        });

    });

    describe("#GreterThan", function() {
        it("#GreterThan - 11 > 10", async () => {
            const w = await circuit.calculateWitness({
                in: "11",
                operator: GREATER,
                value: ["10", "0", "0"],
            }, true);

            await circuit.assertOut(w, {out: 1});
        });

        it("#GreterThan - 11 > 11 (false)", async () => {

            const w1 = await circuit.calculateWitness({
                in: "11",
                operator: GREATER,
                value: ["11", "0", "0"],
            }, true);

            await circuit.assertOut(w1, {out: 0});
        });

        it("#GreterThan - 11 > 12 (false) ", async () => {
            const w2 = await circuit.calculateWitness({
                in: "11",
                operator:  GREATER,
                value: ["12", "0", "0"],
            }, true);

            await circuit.assertOut(w2, {out: 0});
        });

    });

    describe("#IN", function() {
        it("#10 in ['12', '11', '10']", async () => {
            const inputs = {
                in: "10",
                operator:  IN,
                value: ["12", "11", "10"],
            }

            const expOut = {out: 1}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
        });

        it("#11 not IN [`10`, `10`, `0`]", async () => {
            const inputs = {
                in: "11",
                operator:  IN,
                value: ["10", "10", "0"],
            }

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, {out: 0});

        });

    });

    describe("#NOTIN", function() {
        it("#NOTIN 10 not in ['12', '11', '11']", async () => {
            const inputs = {
                in: "10",
                operator:  NOTIN,
                value: ["12", "11", "13"],
            }

            const expOut = {out: 1}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
        });

        it("#NOTIN 10 not in [`10`, `10`, `0`] (false)", async () => {
            const inputs = {
                in: "10",
                operator:  NOTIN,
                value: ["10", "10", "0"],
            }

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, {out: 0});

        });

    });
});
