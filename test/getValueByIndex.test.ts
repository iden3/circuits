import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

const Q = "21888242871839275222246405745257275088548364400416034343698204186575808495616";

describe("credential#getValueByIndex",  function() {
    let circuit;
    let testData = {in:{},expOut:{}};
    const claim =["0",
        "1",
        "2",
        "3",
        "4",
        "5",
        Q,
        "7"];

    before(async function() {
        circuit = await wasm_tester(path.join(__dirname, "circuits/credential", "credential_GetValueByIndex.circom"));
    });

    afterEach( async ()=>{
        const w = await circuit.calculateWitness(testData.in, true);
        await circuit.assertOut(w, testData.expOut);
        circuit.release();
    })

    it("#Get slot index 0", async () => {
        testData.in = {claim: claim, index: "0"};
        testData.expOut = {value: 0};
    });

    it("#Get slot index 1", async () => {
        testData.in = {claim: claim, index: "1"};
        testData.expOut = {value: 1};
    });

    it("#Get slot index 2", async () => {
        testData.in = {claim: claim, index: "2"};
        testData.expOut = {value: 2};
    });

    it("#Get slot index 7 max field value", async () => {
        testData.in = {claim: claim, index: "6"};
        testData.expOut = {value: Q};
    });

    it("#Get slot index 8", async () => {
        testData.in = {claim: claim, index: "7"};
        testData.expOut = {value: 7};
    });
});
