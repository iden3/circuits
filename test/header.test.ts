const path = require("path");
const tester = require("circom_tester").wasm;

export {};

describe("StateTransition", function () {
    this.timeout(600000);

    it("schema in header", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "test.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );

        const inputs = {
              "claim": ["3677203805624134172815825715044445108615", "286312392162647260160287083374160163061246635086990474403590223113720496128", "10", "0", "30803922965249841627828060161", "0", "0", "0"],
        }

        // auth claim   "claim": ["269270088098491255471307608775043319525", "0", "13472757775376226321593595905385246220746328515604713873616318056285586242303", "16586685563688622056787077821051457975731591143161121084121927593789265754171", "0", "0", "0", "0"],

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);

        const expOut = {
            claimType: "274380136414749538182079640726762994055"
        }

        await circuit.assertOut(witness, expOut);
    });

});

