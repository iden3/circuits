import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("authWithRelayer.circom:", async function() {
    const tests = [
        {
            desc: "success",
            input: {
                authClaim: ["251025091000101825075425831481271126140","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],
                authClaimNonRevMtp: ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
                authClaimMtp: ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
                authClaimNonRevMtpAuxHi: "0",
                authClaimNonRevMtpAuxHv: "0",
                authClaimNonRevMtpNoAux: "1",
                challenge: "1",
                challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
                challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
                challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
                claimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
                id: "323416925264666217617288569742564703632850816035761084002720090377353297920",
                revTreeRoot: "0",
                rootsTreeRoot: "0",
                state: "18311560525383319719311394957064820091354976310599818797157189568621466950811",

                reIdenState: "21379323467784491789003100787647318195982639612387659754289889351500654829825",
                hoStateInRelayerClaimMtp: ["17605167619224034183296372581673201279930657375530777790807744693157278638913", "0", "0", "0"],
                reProofValidClaimsTreeRoot: "6406432174442839937842097428557085929352759679431949812924728323765004816196",
                reProofValidRevTreeRoot: "0",
                reProofValidRootsTreeRoot: "0",
            },
            expOut: {
                challenge: 1,
                id: "323416925264666217617288569742564703632850816035761084002720090377353297920",
                state: "18311560525383319719311394957064820091354976310599818797157189568621466950811",
            },
        },
    ];

    let circuit;
    this.timeout(300000)

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits", "authWithRelayer.circom"),
            {
                reduceConstraints: false,
                output: path.join(__dirname, "../circuits", "build/authWithRelayer"),
                recompile: false,
            }
        );
    });

    tests.forEach(({desc, input, expOut}) => {
        it(`auth ${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.assertOut(w, expOut);
        });
    });
});
