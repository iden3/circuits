import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test Nullify template:", async function () {
    const tests = [
        {
            desc: "nullify with all inputs non zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "999",
                claimSchema: "180410020913331409885634153623124536270",
                verifierID: "21929109382993718606847853573861987353620810345503358891473103689157378049",
                verifierSessionID: "94313",
            },
            expOut: { nullifier: "1774255757463994926045333540514329781531189541970510727873068125458049917662" }
        },
        {
            desc: "nullify with verifierSessionID = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "999",
                claimSchema: "180410020913331409885634153623124536270",
                verifierID: "21929109382993718606847853573861987353620810345503358891473103689157378049",
                verifierSessionID: "0",
            },
            expOut: { nullifier: "0" }
        },
        {
            desc: "nullify with credProfileNonce = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "0",
                claimSchema: "180410020913331409885634153623124536270",
                verifierID: "21929109382993718606847853573861987353620810345503358891473103689157378049",
                verifierSessionID: "94313",
            },
            expOut: { nullifier: "0" }
        },
        {
            desc: "nullify with verifierID = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "999",
                claimSchema: "180410020913331409885634153623124536270",
                verifierID: "0",
                verifierSessionID: "94313",
            },
            expOut: { nullifier: "0" }
        },
    ];

    let circuit;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/query/", "nullifyTest.circom"));
    });

    tests.forEach(({ desc, input, expOut }) => {
        it(`${desc}`, async function () {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });
});
