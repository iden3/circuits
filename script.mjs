import * as fs from "fs";
import { execSync } from "child_process";

const CIRCUIT_PARAMS = [
  [10, 10, 16],
  [16, 10, 32],
  [32, 20, 32],
  [32, 40, 64],
];

const CIRCUIT_PATH = "circuits/credentialAtomicQueryV3OnChain.circom";
const INITIAL_INPUTS_JSON_PATH =
  "testvectorgen/credentials/onchain/v3/testdata/mtp/claimIssuedOnProfileID2.json";

for (const [claimLevels, idOwnershipLevels, onChainLevels] of CIRCUIT_PARAMS) {
  // read the circuit file
  const circuit = fs
    .readFileSync(CIRCUIT_PATH, "utf8")
    .replace(
      `credentialAtomicQueryV3OnChain(40, 32, 64, 40, 64)`,
      `credentialAtomicQueryV3OnChain(40, ${claimLevels}, 64, ${idOwnershipLevels}, ${onChainLevels})`
    );

  const circuitsPath = `${
    CIRCUIT_PATH.split(".")[0]
  }-${claimLevels}-${idOwnershipLevels}-${onChainLevels}.circom`;

  const circuitName = circuitsPath.split("/").pop();
  // if (!fs.existsSync(circuitsPath)) {
  fs.existsSync(circuitsPath) && fs.unlinkSync(circuitsPath);

  fs.writeFileSync(circuitsPath, circuit);

  // compile the circuit
  console.log(`Compiling circuit ${circuitName} ...`);
  const executeCommand = `./compile-circuit.sh circuits/${circuitName} pTau/powersOfTau28_hez_final_18.ptau`;
  execSync(executeCommand);
  console.log(`Compiled circuit ${circuitName}`);
  // }

  const json = JSON.parse(
    fs.readFileSync(INITIAL_INPUTS_JSON_PATH, "utf8")
  ).inputs;

  const tempCircuitName = `${circuitName.split(".")[0]}`;
  fs.writeFileSync(
    `build/${tempCircuitName}/${tempCircuitName}_js/input.json`,
    JSON.stringify(
      {
        ...json,
        claimPathMtp: json.claimPathMtp.slice(0, claimLevels),
        authClaimNonRevMtp: json.authClaimNonRevMtp.slice(0, idOwnershipLevels),
        authClaimIncMtp: json.authClaimIncMtp.slice(0, idOwnershipLevels),
        gistMtp: json.gistMtp.slice(0, onChainLevels),
      },
      null,
      2
    )
  );
  console.log(`Generating proof for ${tempCircuitName} ...`);
  execSync(`./generate.sh ${tempCircuitName}`);
  console.log(`Generated proof for ${tempCircuitName}`);
}
