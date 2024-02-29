package utils

import _ "embed"

// List of available operators.
const (
	NOOP int = iota // No operation, skip query verification in circuit
	EQ
	LT
	GT
	IN
	NIN
	NE
	LTE
	GTE
	BETWEEN
	NOT_BETWEEN
	EXISTS
	SD = 16
)

var (
	w3cSchemaURL = "https://www.w3.org/2018/credentials/v1"
	//go:embed w3cSchema.json
	w3cSchemaBody []byte
)

const TestClaimDocument = `{
   "@context": [
     "https://www.w3.org/2018/credentials/v1",
     "https://w3id.org/citizenship/v1",
     "https://w3id.org/security/bbs/v1"
   ],
   "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
   "type": ["VerifiableCredential", "PermanentResidentCard"],
   "issuer": "did:example:489398593",
   "identifier": 83627465,
   "name": "Permanent Resident Card",
   "description": "Government of Example Permanent Resident Card.",
   "issuanceDate": "2019-12-03T12:19:52Z",
   "expirationDate": "2029-12-03T12:19:52Z",
   "credentialSubject": {
     "id": "did:example:b34ca6cd37bbf23",
     "type": ["PermanentResident", "Person"],
     "givenName": "JOHN",
     "familyName": "SMITH",
     "gender": "Male",
     "image": "data:image/png;base64,iVBORw0KGgokJggg==",
     "residentSince": "2015-01-01",
     "lprCategory": "C09",
     "lprNumber": "999-999-999",
     "commuterClassification": "C1",
     "birthCountry": "Bahamas",
     "birthDate": "1958-07-17"
   }
 }`

const TestNormalClaimDocument = `
{
  "id": "urn:uuid:97fbd3d0-8eb7-11ee-8085-a27b3ddbdc29",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld"
  ],
  "type": [
    "VerifiableCredential",
    "KYCAgeCredential"
  ],
  "expirationDate": "2361-03-21T21:14:48+02:00",
  "issuanceDate": "2023-11-29T15:02:47.508637+02:00",
  "credentialSubject": {
    "birthday": 19960424,
    "documentType": 2,
    "id": "did:polygonid:polygon:mumbai:2qDAxLyxvGaGqBLmoDHwohHjtevVdYvpnWcYiK6AcK",
    "type": "KYCAgeCredential"
  },
  "credentialStatus": {
    "id": "http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qGF2TDJZLxzNU1mP3x5PwcUF43vMgdrhRQhaM2HnG/claims/revocation/status/239691578",
    "revocationNonce": 239691578,
    "type": "SparseMerkleTreeProof"
  },
  "issuer": "did:polygonid:polygon:mumbai:2qGF2TDJZLxzNU1mP3x5PwcUF43vMgdrhRQhaM2HnG",
  "credentialSchema": {
    "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/test/cred-array/schemas/json/KYCAgeCredential-v4-arr-list.json",
    "type": "JsonSchema2023"
  }}`

const (
	IdentityTreeLevels = 40
	GistLevels         = 64
	ClaimLevels        = 32
)
