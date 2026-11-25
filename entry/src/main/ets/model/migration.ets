import util from '@ohos.util';
import { AuthenticatorRecord, AuthenticatorType, createAuthenticator, normaliseSecret, OtpAlgorithm, validateAuthenticator } from './otp';

interface VarintResult {
  value: number;
  next: number;
}

interface LengthDelimitedResult {
  value: Uint8Array;
  next: number;
}

interface MigrationParameter {
  secret: Uint8Array;
  name: string;
  issuer: string;
  algorithm: number;
  digits: number;
  type: number;
  counter: number;
}

export function parseGoogleMigrationUri(uri: string): Array<AuthenticatorRecord> {
  const prefix = 'otpauth-migration://offline?';
  if (!uri.toLowerCase().startsWith(prefix)) {
    throw new Error('This is not a Google Authenticator migration URI.');
  }
  const data = migrationData(uri.substring(prefix.length));
  const bytes = decodeBase64(data);
  const authenticators: Array<AuthenticatorRecord> = [];
  let offset = 0;
  while (offset < bytes.length) {
    const tag = readVarint(bytes, offset);
    offset = tag.next;
    const fieldNumber = Math.floor(tag.value / 8);
    const wireType = tag.value % 8;
    if (fieldNumber === 1 && wireType === 2) {
      const field = readLengthDelimited(bytes, offset);
      offset = field.next;
      authenticators.push(convertParameter(parseParameter(field.value)));
    } else {
      offset = skipField(bytes, offset, wireType);
    }
  }
  if (authenticators.length === 0) {
    throw new Error('The migration QR code does not contain any accounts.');
  }
  return authenticators;
}

function migrationData(query: string): string {
  for (const part of query.split('&')) {
    const separator = part.indexOf('=');
    const key = decodeURIComponent((separator < 0 ? part : part.substring(0, separator)).replace(/\+/g, ' '))
      .toLowerCase();
    if (key === 'data' && separator >= 0) {
      return decodeURIComponent(part.substring(separator + 1));
    }
  }
  throw new Error('The migration URI is missing its data field.');
}

function parseParameter(bytes: Uint8Array): MigrationParameter {
  const parameter: MigrationParameter = {
    secret: new Uint8Array(0),
    name: '',
    issuer: '',
    algorithm: 0,
    digits: 0,
    type: 0,
    counter: 0
  };
  let offset = 0;
  while (offset < bytes.length) {
    const tag = readVarint(bytes, offset);
    offset = tag.next;
    const fieldNumber = Math.floor(tag.value / 8);
    const wireType = tag.value % 8;
    if ((fieldNumber === 1 || fieldNumber === 2 || fieldNumber === 3) && wireType === 2) {
      const field = readLengthDelimited(bytes, offset);
      offset = field.next;
      if (fieldNumber === 1) {
        parameter.secret = field.value;
      } else if (fieldNumber === 2) {
        parameter.name = new util.TextDecoder('utf-8').decodeToString(field.value);
      } else {
        parameter.issuer = new util.TextDecoder('utf-8').decodeToString(field.value);
      }
    } else if (fieldNumber >= 4 && fieldNumber <= 7 && wireType === 0) {
      const field = readVarint(bytes, offset);
      offset = field.next;
      if (fieldNumber === 4) parameter.algorithm = field.value;
      if (fieldNumber === 5) parameter.digits = field.value;
      if (fieldNumber === 6) parameter.type = field.value;
      if (fieldNumber === 7) parameter.counter = field.value;
    } else {
      offset = skipField(bytes, offset, wireType);
    }
  }
  return parameter;
}

function convertParameter(parameter: MigrationParameter): AuthenticatorRecord {
  let type: AuthenticatorType;
  if (parameter.type === 1) {
    type = 'HOTP';
  } else if (parameter.type === 2) {
    type = 'TOTP';
  } else {
    throw new Error('A migration account uses an unsupported OTP type.');
  }

  let algorithm: OtpAlgorithm;
  if (parameter.algorithm === 1) {
    algorithm = 'SHA1';
  } else if (parameter.algorithm === 2) {
    algorithm = 'SHA256';
  } else if (parameter.algorithm === 3) {
    algorithm = 'SHA512';
  } else {
    throw new Error('A migration account uses an unsupported hash algorithm.');
  }

  if (parameter.secret.length === 0) {
    throw new Error('A migration account has an empty secret.');
  }
  const issuerText = parameter.issuer.trim();
  const name = parameter.name.trim();
  const issuer = issuerText.length === 0 ? name : issuerText;
  const username = issuerText.length === 0 ? '' : name.replace(`${issuerText}: `, '').trim();
  const record = createAuthenticator(type);
  record.issuer = issuer;
  record.username = username;
  record.secret = normaliseSecret(type, encodeBase32(parameter.secret));
  record.algorithm = algorithm;
  record.digits = parameter.digits === 2 ? 8 : 6;
  record.counter = parameter.counter;
  return validateAuthenticator(record);
}

function readVarint(bytes: Uint8Array, start: number): VarintResult {
  let value = 0;
  let multiplier = 1;
  let offset = start;
  while (offset < bytes.length && offset - start < 8) {
    const current = bytes[offset];
    offset++;
    value += (current & 0x7f) * multiplier;
    if (current < 0x80) {
      if (!Number.isSafeInteger(value)) {
        throw new Error('The migration QR code contains an unsupported integer.');
      }
      const result: VarintResult = { value, next: offset };
      return result;
    }
    multiplier *= 128;
  }
  throw new Error('The migration QR code contains an invalid protobuf value.');
}

function readLengthDelimited(bytes: Uint8Array, start: number): LengthDelimitedResult {
  const length = readVarint(bytes, start);
  const end = length.next + length.value;
  if (end > bytes.length) {
    throw new Error('The migration QR code is truncated.');
  }
  const result: LengthDelimitedResult = { value: bytes.slice(length.next, end), next: end };
  return result;
}

function skipField(bytes: Uint8Array, start: number, wireType: number): number {
  if (wireType === 0) {
    return readVarint(bytes, start).next;
  }
  if (wireType === 1) {
    return checkedOffset(bytes, start, 8);
  }
  if (wireType === 2) {
    return readLengthDelimited(bytes, start).next;
  }
  if (wireType === 5) {
    return checkedOffset(bytes, start, 4);
  }
  throw new Error('The migration QR code contains an unsupported protobuf field.');
}

function checkedOffset(bytes: Uint8Array, start: number, length: number): number {
  const end = start + length;
  if (end > bytes.length) {
    throw new Error('The migration QR code is truncated.');
  }
  return end;
}

function decodeBase64(input: string): Uint8Array {
  const value = input.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const bytes: Array<number> = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of value) {
    if (character === '=') {
      break;
    }
    const digit = alphabet.indexOf(character);
    if (digit < 0) {
      throw new Error('The migration URI contains invalid Base64 data.');
    }
    accumulator = (accumulator << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
    }
  }
  if (bits === 6) {
    throw new Error('The migration URI contains incomplete Base64 data.');
  }
  return new Uint8Array(bytes);
}

function encodeBase32(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let accumulator = 0;
  let bits = 0;
  let result = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet.charAt((accumulator >> bits) & 0x1f);
    }
  }
  if (bits > 0) {
    result += alphabet.charAt((accumulator << (5 - bits)) & 0x1f);
  }
  return result;
}
