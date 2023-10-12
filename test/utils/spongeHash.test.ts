import * as fs from "fs";
import path from "path";
import { wasm } from "circom_tester";

const templateName = "SpongeHash";
const relativePath = "../circuits";
const generateTemplate = (
  size: number,
  circuitTemplateName = "SpongeHash"
): void => {
  const template = `
pragma circom 2.1.1;
include "../../circuits/lib/utils/spongeHash.circom";
template ${circuitTemplateName}Test() {
signal input in[{{n}}];
signal output out;
component h = ${circuitTemplateName}({{n}},6);
for(var i = 0; i < {{n}}; i++) {
h.in[i] <== in[i];
}
out <== h.out;
}
component main = ${circuitTemplateName}Test();
`;

  const circuitName = `${circuitTemplateName}${size}.circom`;
  if (!fs.existsSync(path.join(__dirname, relativePath, circuitName))) {
    fs.writeFileSync(
      path.join(__dirname, relativePath, circuitName),
      template.replace(/{{n}}/g, size.toString())
    );
  }
};

describe("Sponge Hash tests", function () {
  this.timeout(400000);
  it("Test SpongeHash util using hash for different size inputs", async () => {
    const testCases = [
      new Array(64).fill(0),
      new Array(63).fill(0).map((_, i) => i + 1),
      new Array(60).fill(0).map((_, i) => 60 - i),
      new Array(5).fill(0).map((_, i) => i + 1),
      [0],
      new Array(6).fill(0).map((_, i) => i + 1),
      new Array(16).fill(0).map((_, i) => i + 1),
    ];

    const expected = [
      "7368935780301629035733097554153370898490964345621267223639562510928947240459",
      "3027148895471770401984833121350831002277377476084832804937751928355120074994",
      "13254546416358473313457812414193018870743005197521155619424967381510427667259",
      "6186895146109816025093019628248576250523388957868658785525378722128520330607",
      "14408838593220040598588012778523101864903887657864399481915450526643617223637",
      "20400040500897583745843009878988256314335038853985262692600694741116813247201",
      "5605330091169856132381694679994923791994681609858984566508182442210285386845",
    ];

    await createCircuit(testCases, expected);
  });

  it("Compare SpongeHash with go-iden3-crypto", async () => {
    const expected = [
      "7757418611592686851480213421395023492910069335464834810473637859830874759279",
      "15336558801450556532856248569924170992202208561737609669134139141992924267169",
      "1144067817111460038464347636467015864025755473684726783913963849059920017972",
      "17412321031092738336952455023828291176350572898965143678124844674611030278684",
      "6186895146109816025093019628248576250523388957868658785525378722128520330607",
      "20400040500897583745843009878988256314335038853985262692600694741116813247201",
      "5577102071379540901883430718956859114277228199376926918690006383418752242436",
      "1152305401687934645444055619201663931885907446826162025284948369145242973368",
      "8211686227523893359273736667704216885003209084307215502943363750368107369620",
      "7108881484930248270303049372327318360896856726757123411260066018366897025567",
      "2265321027947983264707184154085264659877433648022878713272356019112959947364",
      "12651359110916308876830620694657526370832930110397701742810260795463743022206",
      "5448696623590242880008365208951082811870613001921911478755586779573529615712",
      "12138957412533147284529235731676849096990688866708298976199544475739215311830",
      "4296304251107177078079123684673490646100950885652358062546507066452904816259",
      "5605330091169856132381694679994923791994681609858984566508182442210285386845",
      "13988934542900192765733497388343315006075364569889174469414974142779436870312",
      "15403024279602420951485303794282139684443426339931496210157338841814828581711",
      "21456291545549982243960095968662564139932500401819177068272967144559313156981",
      "18204869441381241555967353898895621136239168759533159329850061388567652528934",
      "13038015408593191211490686165474468640092531721798660195788216465453248480728",
    ];

    const testCases = expected.map((_, i) =>
      new Array(i + 1).fill(0).map((_, i) => i + 1)
    );

    await createCircuit(testCases, expected);
  });

  async function createCircuit(testCases: number[][], expected: string[]) {
    for (let index = 0; index < expected.length; index++) {
      generateTemplate(testCases[index].length);
      const circuit = await wasm(
        path.join(
          __dirname,
          relativePath,
          `${templateName}${testCases[index].length}.circom`
        )
      );

      const witness = await circuit.calculateWitness({
        in: testCases[index],
      });
      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, {
        out: expected[index],
      });

      fs.unlinkSync(
        path.join(
          __dirname,
          relativePath,
          `${templateName}${testCases[index].length}.circom`
        )
      );
    }
  }
});
