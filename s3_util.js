const AWS = require('aws-sdk');
const AdmZip = require('adm-zip');
const path = require('path');

const BUCKET_NAME = 'iden3-circuits-bucket';
const FILES_TO_INCLUDE = ['.wasm', 'final.zkey', 'key.json', 'readme'];
const FOLDER_TO_COMPRESS = './build';
const OPERATIONS = ['add', 'rm', 'zip'];

function main() {
    const [operation, zipName] = parseArgs();
    processOperation(operation, zipName);
    // console.log(operation, zipName)
}

main();

function processOperation(operation, zipName) {
    try {
        switch (operation) {
            case 'add': uploadZipFile(zipName)
                break;
            case 'rm': deleteFile(zipName)
                break;
            case 'zip':
                const zip = makeZip(zipName)
                console.log(`Starting saving zip...`);
                zip.writeZip(zipName);
                console.log(`Zip successfully saved: ${path.join(process.cwd(), zipName)}`);
                break;
            default:
                console.error(`Operation ${operation} is not supported`)
                break;
        }
    } catch (error) {
        console.error(error)
        process.exit(1)
    }
}

function parseArgs() {
    let [operation, zipName] = process.argv.slice(2);

    if (!OPERATIONS.includes(operation)) {
        console.error(`Error! Supported operations: ${OPERATIONS.join(', ')}`);
        process.exit(1)
    }

    if (!zipName) {
        console.error(`please provide name for zip file as argument, for example 'node s3_upload.js add v1.zip'`)
        process.exit(1)
    }

    zipName = !zipName.includes('.zip') ? `${zipName}.zip` : zipName;

    return [operation, zipName];
};

function uploadZipFile(zipName) {
    const s3 = new AWS.S3({
        accessKeyId: process.env.ACCESS_KEY_ID,
        secretAccessKey: process.env.SECRET_ACCESS_KEY
    });

    const zip = makeZip()

    console.log('Creating zip buffer...');
    const params = {
        Bucket: BUCKET_NAME,
        Key: zipName,
        Body: zip.toBuffer()
    };
    console.log('Buffer successfully created')

    // Uploading files to the bucket
    const uploading = s3.upload(params, function (err, data) {
        if (err) {
            console.error(err.message ?? err);
            throw err;
        }
        console.info(`Zip file uploaded successfully. ${data.Location}`);
    });

    trackProgressFor(uploading);
};


function makeZip() {
    console.info(`Starting creation of zip file...`);
    const zip = new AdmZip();
    zip.addLocalFolder(FOLDER_TO_COMPRESS, '', name => FILES_TO_INCLUDE.some(ext => name.includes(ext)));
    return zip;
}

function deleteFile(zipName) {
    console.info(`Starting deleting of ${zipName} from ${BUCKET_NAME}...`);

    const s3 = new AWS.S3({
        accessKeyId: process.env.ACCESS_KEY_ID,
        secretAccessKey: process.env.SECRET_ACCESS_KEY
    });

    // Setting up S3 upload parameters
    const params = {
        Bucket: BUCKET_NAME,
        Key: zipName
    };

    // Uploading files to the bucket
    const deletion = s3.deleteObject(params, function (err, data) {
        if (err) {
            console.error(err.message ?? err);
            throw err;
        }
        console.log(`File ${zipName} successfully deleted.`);
    });

    trackProgressFor(deletion);
}

function trackProgressFor(source) {
    source.on('httpUploadProgress', ({ loaded, total }) => {
        if (loaded && total) console.log(`Progress: ${Math.floor(loaded / total * 100)}%`);
    });
}
