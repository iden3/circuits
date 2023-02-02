const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test on-chain ZK verification example", function () {

      this.timeout(600000);

      let circuit;

      before(async () => {
          circuit = await wasm_tester(
              path.join(__dirname, "../circuits", "onChainZKVerificationExample.circom"),
              {
                  output: path.join(__dirname, "circuits", "build"),
                  recompile: true,
                  reduceConstraints: false,
              },
          );

      });

      after(async () => {
          circuit.release()
      })

      it("test onChainZKVerificationExample", async () => {

        const inputs = {
          "issuerPubKeyAx": "4720763745722683616702324599137259461509439547324750011830105416383780791263",
          "issuerPubKeyAy": "4844030361230692908091131578688419341633213823133966379083981236400104720538",
          "issuerClaimSignatureR8x": "12230450915698177828238748666457663013222607250319116988777214594591574422592",
          "issuerClaimSignatureR8y": "3113664026928507428134616202169241412463038751700720695351271642533922323823",
          "issuerClaimSignatureS": "2491285233655070555506650500149558285030657885296100030672330833069796802045",
          "userEthereumAddressInClaim": "583091486781463398742321306787801699791102451699",
          "userAgeInClaim": "25",
          "userMinAge": "18"
        }

        const expOut = {}
        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, expOut);
      });


      it("sfdd", async () => {
        var s = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";             // translate to hexadecimal notation
        s = s.replace(/^(.(..)*)$/, "0$1"); // add a leading zero if needed
        var a = s.match(/../g);             // split number in groups of two
        a.reverse();                        // reverse the groups
        var s2 = a.join("");                // join the groups back together
        console.log(s2);
      });
})
