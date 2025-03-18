pragma circom 2.0.0;

// dg1TagSize size of tag before dg1 content
function dg1TagSize() {
  return 5;
}

// Document code: Original Position 1, Size 2 (0-indexed: 0)
function documentCodePosition() {
  return 0 + dg1TagSize();
}
function documentCodeSize() {
  return 2;
}

// Issuing State or organization: Original Position 3, Size 3 (0-indexed: 2)
function issuingStatePosition() {
  return 2 + dg1TagSize();
}
function issuingStateSize() {
  return 3;
}

// Name of holder: Original Position 6, Size 39 (0-indexed: 5)
function nameOfHolderPosition() {
  return 5 + dg1TagSize();
}
function nameOfHolderSize() {
  return 39; // Holder size for TD3
}

// Document number: Originally on second line (Position 1, Size 9), now concatenated: Position 44, Size 9
function documentNumberPosition() {
  return 44 + dg1TagSize();
}
function documentNumberSize() {
  return 9;
}

// Nationality: Originally on second line (Position 11, Size 3), now concatenated: Position 54, Size 3
function nationalityPosition() {
  return 54 + dg1TagSize();
}
function nationalitySize() {
  return 3;
}

// DOB: Originally on second line (Position 14, Size 6), now concatenated: Position 57, Size 6
function dobPosition() {
  return 57 + dg1TagSize();
}
function dobSize() {
  return 6;
}

// Sex: Originally on second line (Position 21, Size 1), now concatenated: Position 64, Size 1
function sexPosition() {
  return 64 + dg1TagSize();
}
function sexSize() {
  return 1;
}

// Date of expiry: Originally on second line (Position 22, Size 6), now concatenated: Position 65, Size 6
function dateOfExpiryPosition() {
  return 65 + dg1TagSize();
}
function dateOfExpirySize() {
  return 6;
}

function getMaxDSCLength(){
    return 1792;
}

// Symbol '<' in ASCII encoding
function mrzDelimiterSymbol() {
    return 60; // <
}

// Symbol ' ' (space) in ASCII encoding
function spaceSymbol() {
    return 32;
}

// Size of MZR or DG1 (with tag)
function MZR_TD3_SIZE() {
    return 93;
}

// Max chunks bytes for Poseidon chunk
function chunkSize() {
    return 31;
}

// Max Poseidon chunks
function chunkCount() {
    return 16;
}

// Max Poseidon message size
function messageMaxSize() {
    return chunkSize() * chunkCount();
}

// Part of hashIndex. V0
function v0() {
  return 14477845612645806574444905890781353993111;
}

function MZR_TD3_SIZE_BITS() {
  return MZR_TD3_SIZE() * 8;
}