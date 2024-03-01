const dataFolder = './testvectorgen/contract_data/testdata/v3';
const contractDataBaseFolder = '../contracts/test/validators/';
const buildFolder = './build/';
const fs = require('fs');
const path = require('path');
const { execSync, execFileSync } = require('child_process');

const files = fs.readdirSync(dataFolder);

let circuitName = null;
let destinationFolder = null;
for (const file of files) {


  if (file.includes('state')) {
    circuitName = 'stateTransition'
    destinationFolder = 'common-data'
  } else {
    circuitName = 'credentialAtomicQueryV3OnChain-beta.1'
    destinationFolder = 'v3/data'
  }
  const buildPath = `./build/${circuitName}/${circuitName}_js/`;
  ['input.json', 'public.json', 'proof.json'].forEach((f) => {
    const p = path.join(`./build/${circuitName}/${circuitName}_js`, f)
    fs.existsSync(p) &&
      fs.unlinkSync(p);
    console.log(`Deleted file: ${p}`);
  });
  const { inputs } = require(`${dataFolder}/${file}`);
  console.log(`Reading file: ${dataFolder}/${file}`);

  console.log(`Creating file: ${buildPath}/input.json`);
  fs.writeFileSync(`${buildPath}/input.json`, JSON.stringify(inputs), 'utf-8');
  const child = execSync(`./generate.sh ${circuitName}`);
  console.log(`execution completed`, new TextDecoder().decode(child));
  const pub_signals = JSON.parse(fs.readFileSync(`${buildPath}/public.json`).toString());
  console.log(pub_signals);
  const proof = JSON.parse(fs.readFileSync(`${buildPath}/proof.json`).toString());
  console.log('Writing file: ', `${contractDataBaseFolder}/${destinationFolder}/${file}`);
  fs.writeFileSync(`${contractDataBaseFolder}/${destinationFolder}/${file}`, JSON.stringify({
    pub_signals,
    proof
  }), 'utf-8');

}

console.log('Done');
