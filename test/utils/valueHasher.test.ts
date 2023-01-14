import * as fs from "fs";
import path from "path";
import { wasm } from "circom_tester";

const relativePath = "../circuits";
const generateTemplate = (templateName: string, size: number): void => {
    const template = `
pragma circom 2.0.0;
include "../../circuits/lib/utils/valueHasher.circom";
template ${templateName}Test() {
signal input in[{{n}}];
signal output out;
component h = ${templateName}({{n}});
for(var i = 0; i < {{n}}; i++) {
h.in[i] <== in[i];
}
out <== h.out;
}
component main = ${templateName}Test();
`;

    const circuitName = `${templateName}${size}.circom`;
    if (!fs.existsSync(path.join(__dirname, relativePath, circuitName))) {
        fs.writeFileSync(
            path.join(__dirname, relativePath, circuitName),
            template.replace(/{{n}}/g, size.toString())
        );
    }
};


describe("Value Hasher tests", function () {
    this.timeout(200000);
    it("Test ValueHasher util using hash for different size inputs", async () => {
        const templateName = "ValueHasher";
        const testCases = [
            new Array(64).fill(0),
            new Array(63).fill(0).map((_, i) => i + 1),
            new Array(60).fill(0).map((_, i) => 60 - i),
            new Array(5).fill(0).map((_, i) => i + 1),
            [0],
            new Array(6).fill(0).map((_, i) => i + 1),

        ];

        const expected = [
            "7368935780301629035733097554153370898490964345621267223639562510928947240459",
            "3027148895471770401984833121350831002277377476084832804937751928355120074994",
            "13254546416358473313457812414193018870743005197521155619424967381510427667259",
            "6186895146109816025093019628248576250523388957868658785525378722128520330607",
            "14408838593220040598588012778523101864903887657864399481915450526643617223637",
            "20400040500897583745843009878988256314335038853985262692600694741116813247201"
        ];

        for (let index = 0; index < testCases.length; index++) {
            generateTemplate(templateName, testCases[index].length);
            const circuit = await wasm(
                path.join(__dirname, relativePath, `${templateName}${testCases[index].length}.circom`),
                { reduceConstraints: false }
            );

            const witness = await circuit.calculateWitness({
                in: testCases[index]
            });
            await circuit.checkConstraints(witness);
            await circuit.assertOut(witness, {
                out: expected[index]
            });

            fs.unlinkSync(path.join(__dirname, relativePath, `${templateName}${testCases[index].length}.circom`));
        }

    });

})
