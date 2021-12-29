import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe('auth.circom:', async function () {
    const tests = [
        {
            desc: 'success',
            input: {
                "BBJAx": "9582165609074695838007712438814613121302719752874385708394134542816240804696",
                "BBJAy": "18271435592817415588213874506882839610978320325722319742324814767882756910515",
                "BBJClaimClaimsTreeRoot": "4648350302718598839424502774166524253703556728225603109003078358379460427828",
                "challenge": "12345",
                "challengeSignatureR8x": "16612725446091862317820229560908560785741846639564668282377389669494210791554",
                "challengeSignatureR8y": "16389928442818324712810234717861061407506363761548062772318825166082227839220",
                "challengeSignatureS": "2734509058284749305743301031511411294322326439393517308790764830820315443120",
                "id": "360506537017543098982364518145035624387547643177965411252793105868750389248",
                "state": "12051733342209181702880711377819237050140862582923079913097401558944144010618"
            }
            ,
            expOut: {
                challenge: 12345,
                id: "360506537017543098982364518145035624387547643177965411252793105868750389248",
                state: "12051733342209181702880711377819237050140862582923079913097401558944144010618"
            }
        }

    ];

    let circuit;
    this.timeout(10000)

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "../../circuits/examples", "auth.circom"));
    });

    tests.forEach(({desc, input, expOut}) => {
        it(`auth ${desc}`, async function () {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
        });
    });
});
