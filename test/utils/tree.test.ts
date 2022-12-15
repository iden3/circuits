import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test tree",  function() {
    this.timeout(10000)

    let circuit;
    let testData = {in:{},expOut:{}};

    before(async function() {
        console.log("before function")
        circuit = await wasm_tester(path.join(__dirname, "../circuits/utils", "utils_tree.circom"));
    });

    afterEach( async ()=>{
        const w = await circuit.calculateWitness(testData.in, true);
        await circuit.assertOut(w, testData.expOut);
    })

    it("#success claim with expiration time", async () => {
        const claim = ["301485908906857522017021291028488077057", "0", "0", "0", "0", "0", "0", "0"];
        const mtp = ["8493457070992886300428662071037166757566859141363961223639921512939583703225", "8485562453225409715331824380162827639878522662998299574537757078697535221073", "9054077202653694725190129562729426419405710792276939073869944863201489138082", "3108394280857290448796042949317662357879960495408018998613518544538624657019", "0", "16390924951002018924619640791777477120654009069056735603697729984158734051481", "0", "0", "0", "0", "0"]
        const root = "2979985488157533386043177661003637977133216759544939475202992175849348216681"

        testData.in = {
            claim: claim,
            mtp: mtp,
            root: root,
        };
        testData.expOut = {out: 1};
    });
});
