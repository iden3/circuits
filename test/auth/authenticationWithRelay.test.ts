import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("authWithRelay.circom:", async function() {
    const tests = [
        {
            desc: "success",
            input: {
                userClaimsTreeRoot: "9763429684850732628215303952870004997159843236039795272605841029866455670219",
                userAuthClaimMtp: ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
                userAuthClaim: ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
                userRevTreeRoot: "0",
                userAuthClaimNonRevMtp: ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
                userAuthClaimNonRevMtpNoAux: "1",
                userAuthClaimNonRevMtpAuxHi: "0",
                userAuthClaimNonRevMtpAuxHv: "0",

                userRootsTreeRoot: "0",

                challenge: "1",
                challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
                challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
                challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",

                userState: "18656147546666944484453899241916469544090258810192803949522794490493271005313",
                userID: "379949150130214723420589610911161895495647789006649785264738141299135414272",

                relayState: "18208153479332983124870480188219322324164347189995584127609789781633407387346",
                userStateInRelayClaimMtp:  ["0","0","11520880954845029687314622548841638077246807477650633130209067753688100437132","0"],
                userStateInRelayClaim: ["795467278703584189433295357807347445218","379949150130214723420589610911161895495647789006649785264738141299135414272","0","0","0","0","18656147546666944484453899241916469544090258810192803949522794490493271005313","0"],
                relayProofValidClaimsTreeRoot: "16805899569766033942837969984651606090455862530303031568886007270655722173020",
                relayProofValidRevTreeRoot: "0",
                relayProofValidRootsTreeRoot: "0",
            },
        },
    ];

    let circuit;
    this.timeout(300000)

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits", "authWithRelayTest.circom"),
            {
                reduceConstraints: false,
                output: path.join(__dirname, "../circuits", "build/authWithRelay"),
                recompile: true,
            }
        );
    });

    tests.forEach(({desc, input}) => {
        it(`auth ${desc}`, async () => {
            const w = await circuit.calculateWitness(input, true);
            await circuit.checkConstraints(w);
        });
    });
});
