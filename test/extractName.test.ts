import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;

// export {};

describe("String extractName.circom", function() {

  this.timeout(600000);

  let circuit;

  before(async () => {
      circuit = await wasmTester(
          path.join(__dirname, "../circuits/", "extractName.circom"),
          {
              output: path.join(__dirname, "circuits", "build"),
              recompile: true,
              include: [
                path.join(__dirname, '../node_modules'),
              ],
          },
      );

  });

  after(async () => {
      circuit.release()
  })

  it(`Test string processor`, async function() {
    const docs = "SOLID<<YAROSLAV<<<<<<<<<<<<<<<<<<<<<<<<";
    const encoder = new TextEncoder();
    const byteArray = encoder.encode(docs);
    console.log(byteArray.length);
    console.log(byteArray);
    const inputs = {
        arr: [...byteArray],
        firstNameLen: 5,
        secondNameLen: 8 
    }
    const w = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(w);
  });

});
