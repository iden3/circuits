// TODO (illia-korotia): need review and refactor. Do not trust this code :)

/**
 * Generates a passport MRZ (Machine Readable Zone) string
 * @param documentType Document type (usually 'P' for passport)
 * @param issuingCountry 3-letter country code (ISO 3166-1 alpha-3)
 * @param surname Surname of the holder
 * @param givenNames Given names of the holder
 * @param passportNumber Passport number (max 9 characters)
 * @param nationality 3-letter country code (ISO 3166-1 alpha-3)
 * @param dateOfBirth Date of birth in YYMMDD format
 * @param gender Gender ('M', 'F', or 'X')
 * @param dateOfExpiry Date of expiry in YYMMDD format
 * @param personalNumber Optional personal number
 * @returns Object containing MRZ string, surname size, and given names size
 */
export function generateMRZ(
  documentType: string,
  issuingCountry: string,
  surname: string,
  givenNames: string,
  passportNumber: string,
  nationality: string,
  dateOfBirth: string,
  gender: string,
  dateOfExpiry: string,
  personalNumber: string = ''
): { mrz: string; surnameSize: number; givenNamesSize: number } {
  // Convert to uppercase and replace special characters
  const formattedSurname = formatName(surname);
  const formattedGivenNames = formatName(givenNames);
  
  // First line: Document type, issuing country, and name
  const namePart = `${formattedSurname}<<${formattedGivenNames}`;
  const line1 = padRight(`${documentType}<${issuingCountry}${namePart}`, 44, '<');
  
  // Second line: Passport number, nationality, date of birth, gender, expiry date, personal number
  // Pad passport number to exactly 9 characters
  const paddedPassportNumber = padRight(passportNumber, 9, '<');
  const passportNumberWithCheckDigit = `${paddedPassportNumber}${calculateCheckDigit(paddedPassportNumber)}`;
  const nationalityPart = nationality;
  const dobWithCheckDigit = `${dateOfBirth}${calculateCheckDigit(dateOfBirth)}`;
  const expiryWithCheckDigit = `${dateOfExpiry}${calculateCheckDigit(dateOfExpiry)}`;
  
  // Ensure personal number part is always 14 characters + 1 check digit = 15 characters
  const paddedPersonalNumber = padRight(personalNumber, 14, '<');
  const personalNumberWithCheckDigit = `${paddedPersonalNumber}${calculateCheckDigit(paddedPersonalNumber)}`;
  
  // Calculate final check digit for line 2
  const line2Data = `${paddedPassportNumber}${calculateCheckDigit(paddedPassportNumber)}${nationalityPart}${dateOfBirth}${calculateCheckDigit(dateOfBirth)}${gender}${dateOfExpiry}${calculateCheckDigit(dateOfExpiry)}${paddedPersonalNumber}`;
  const finalCheckDigit = calculateCheckDigit(line2Data);
  
  // Construct line 2
  const line2 = `${passportNumberWithCheckDigit}${nationalityPart}${dobWithCheckDigit}${gender}${expiryWithCheckDigit}${personalNumberWithCheckDigit}${finalCheckDigit}`;
  
  return {
    mrz: `${line1}${line2}`,
    surnameSize: formattedSurname.length,
    givenNamesSize: formattedGivenNames.length
  };
}

/**
 * Formats a name for MRZ by converting to uppercase and replacing special characters
 * @param name Name to format
 * @returns Formatted name
 */
function formatName(name: string): string {
  return name
    .toUpperCase()
    .replace(/[^\w]/g, '<')
    .replace(/\s+/g, '<');
}

/**
 * Pads a string to a specified length with a specified character
 * @param str String to pad
 * @param length Target length
 * @param padChar Character to pad with
 * @returns Padded string
 */
function padRight(str: string, length: number, padChar: string): string {
  return str.length >= length ? str.substring(0, length) : str + padChar.repeat(length - str.length);
}

/**
 * Calculates the check digit for MRZ
 * @param str String to calculate check digit for
 * @returns Check digit character
 */
function calculateCheckDigit(str: string): string {
  const weights = [7, 3, 1];
  let sum = 0;
  
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    let value: number;
    
    if (/[0-9]/.test(char)) {
      value = parseInt(char, 10);
    } else if (/[A-Z]/.test(char)) {
      value = char.charCodeAt(0) - 55; // A=10, B=11, etc.
    } else if (char === '<') {
      value = 0;
    } else {
      value = 0;
    }
    
    sum += value * weights[i % 3];
  }
  
  return (sum % 10).toString();
}