import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};


const EQUALS  = "0"; // = - equals sign
const LESS    = "1"; // = - less-than sign
const GREATER = "2"; // = - greater-than sign

describe("Test simpleQuery",  function() {
    let circuit;

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "../circuits", "simpleQuery_test.circom"));
    });

    describe("#IsEqual", function (){
        it("#IsEqual - true", async () => {
            const inputs = {
                field: "10",
                sign:  EQUALS,
                value: "11",
            }

            const expOut = {out: 0}

            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
        });

        it("#IsEqual - false", async () => {
            const inputs = {
                field: "10",
                sign:  EQUALS,
                value: "11",
            }

            const w = await circuit.calculateWitness({
                field: "10",
                sign:  "0",
                value: "10",
            }, true);
            await circuit.assertOut(w, {out: 1});

        });

        it.skip("#IsEqual - 0", async ()=>{
            // TODO:
        })
        it.skip("#IsEqual - MaxValue", async ()=>{
            // TODO:
        })
    });

    describe("#LessThan", function (){
        it("#LessThan - 10 > 11", async () => {
            let w = await circuit.calculateWitness({
                field: "10",
                sign: LESS,
                value: "11",
            }, true);

            await circuit.assertOut(w, {out: 1});
        });

        it("#LessThan - 10 = 10", async () => {


            const w1 = await circuit.calculateWitness({
                field: "10",
                sign: LESS,
                value: "10",
            }, true);

            await circuit.assertOut(w1, {out: 0});
        });

        it("#LessThan - 10 > 9", async () => {
            const w2 = await circuit.calculateWitness({
                field: "10",
                sign:  LESS,
                value: "9",
            }, true);

            await circuit.assertOut(w2, {out: 0});
        });

        it.skip("#LessThan - 0", async ()=>{
            // TODO:
        })
        it.skip("#LessThan - MaxValue", async ()=>{
            // TODO:
        })
    });

    describe("#GreaterThan", function (){
        //TODO:
    });
});
