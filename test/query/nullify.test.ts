import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test Nullify operator:", async function () {
    const tests = [
        {
            desc: "nullify with all inputs non zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "999",
                claimSchema: "180410020913331409885634153623124536270",
                fieldValue: "10",
                verifierID: "21929109382993718606847853573861987353620810345503358891473103689157378049",
                crs: "94313",
            },
            expOut: { nullifier: "2087978292462493888670232038371828714766286629966158700504811197876900431862" }
        },
        {
            desc: "nullify with csr = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "999",
                claimSchema: "180410020913331409885634153623124536270",
                fieldValue: "10",
                verifierID: "21929109382993718606847853573861987353620810345503358891473103689157378049",
                crs: "0",
            },
            expOut: { nullifier: "726655184513479858506545456523347580294479110324074029543303083957717308550" }
        },
        {
            desc: "nullify with credProfileNonce = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "0",
                claimSchema: "180410020913331409885634153623124536270",
                fieldValue: "10",
                verifierID: "21929109382993718606847853573861987353620810345503358891473103689157378049",
                crs: "94313",
            },
            expOut: { nullifier: "0" }
        },
        {
            desc: "nullify with verifierID = zero",
            input: {
                genesisID: "23148936466334350744548790012294489365207440754509988986684797708370051073",
                claimSubjectProfileNonce: "999",
                claimSchema: "180410020913331409885634153623124536270",
                fieldValue: "10",
                verifierID: "0",
                crs: "94313",
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
