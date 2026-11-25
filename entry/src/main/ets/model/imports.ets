import { common } from '@kit.AbilityKit';
import { relationalStore } from '@kit.ArkData';
import { fileIo } from '@kit.CoreFileKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { taskpool } from '@kit.ArkTS';
import { inflateRaw as decompressRawDeflate } from '@ohos/flate2';
import { argon2id, type ArgonOpts } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as kdbxweb from 'kdbxweb';
import { ohosArgon2 } from 'kdbxweb/src/main/ets/crypto/argon2-rs';
import { xchacha20poly1305 } from './noble-ciphers/chacha.js';
import { AuthenticatorRecord, AuthenticatorType, categoryIdForName, createAuthenticator, emptyVault, OtpAlgorithm, parseOtpUri, toBase32Bytes, utf8Bytes, validateAuthenticator, VaultData } from './otp';
import { iconKeyForIssuer } from './iconresolver';
import util from '@ohos.util';

export type ExternalImportFormat =
  'andotp' | 'freeotp' | 'freeotp-plus' | 'aegis' | 'bitwarden' | 'ente' | 'proton' | 'winauth' |
  'twofas' | 'keepass' | 'lastpass' | 'totp-authenticator' | 'authenticator-plus' | 'uri-list';

export type ImportPasswordPolicy = 'never' | 'always' | 'maybe';

export interface ExternalImportOption {
  format: ExternalImportFormat;
  label: string;
  passwordPolicy: ImportPasswordPolicy;
}

export interface ExternalImportResult {
  vault: VaultData;
  failures: Array<string>;
}

interface DerCursor {
  offset: number;
}

interface FreeOtpParameters {
  iv: Uint8Array;
  macLength: number;
}

export const EXTERNAL_IMPORT_OPTIONS: Array<ExternalImportOption> = [
  { format: 'andotp', label: 'andOTP', passwordPolicy: 'maybe' },
  { format: 'freeotp', label: 'FreeOTP', passwordPolicy: 'always' },
  { format: 'freeotp-plus', label: 'FreeOTP+', passwordPolicy: 'never' },
  { format: 'aegis', label: 'Aegis', passwordPolicy: 'maybe' },
  { format: 'bitwarden', label: 'Bitwarden', passwordPolicy: 'maybe' },
  { format: 'ente', label: 'Ente Auth', passwordPolicy: 'maybe' },
  { format: 'proton', label: 'Proton Authenticator', passwordPolicy: 'never' },
  { format: 'winauth', label: 'WinAuth', passwordPolicy: 'maybe' },
  { format: 'twofas', label: '2FAS', passwordPolicy: 'maybe' },
  { format: 'keepass', label: 'KeePass', passwordPolicy: 'always' },
  { format: 'lastpass', label: 'LastPass Authenticator', passwordPolicy: 'never' },
  { format: 'totp-authenticator', label: 'TOTP Authenticator', passwordPolicy: 'always' },
  { format: 'authenticator-plus', label: 'Authenticator Plus', passwordPolicy: 'always' },
  { format: 'uri-list', label: 'URI list', passwordPolicy: 'never' }
];

export class ImportPasswordRequiredError extends Error {
  constructor(message: string = 'Enter the password for this backup.') {
    super(message);
    this.name = 'ImportPasswordRequiredError';
  }
}

const TEXT_DECODER = new util.TextDecoder('utf-8');
const BASE64 = new util.Base64Helper();
const EMPTY_BYTES = new Uint8Array(0);

export async function convertExternalBackup(format: ExternalImportFormat, data: Uint8Array,
  password: string = '', context?: common.Context): Promise<ExternalImportResult> {
  if (data.length === 0 || data.length > 32 * 1024 * 1024) {
    throw new Error('The selected import file is empty or too large.');
  }
  switch (format) {
    case 'andotp':
      return await convertAndOtp(data, password);
    case 'freeotp':
      return await convertFreeOtp(data, password);
    case 'winauth':
      return await convertWinAuth(data, password);
    case 'keepass':
      return await convertKeePass(data, password);
    case 'uri-list':
      return convertUriList(data);
    case 'freeotp-plus':
      return convertFreeOtpPlus(data);
    case 'aegis':
      return await convertAegis(data, password);
    case 'twofas':
      return await convertTwoFas(data, password);
    case 'bitwarden':
      return await convertBitwarden(data, password);
    case 'ente':
      return await convertEnte(data, password);
    case 'proton':
      return convertProton(data);
    case 'lastpass':
      return convertLastPass(data);
    case 'totp-authenticator':
      return await convertTotpAuthenticator(data, password);
    case 'authenticator-plus':
      if (context === undefined) {
        throw new Error('The application context is required to read Authenticator Plus backups.');
      }
      return await convertAuthenticatorPlus(data, password, context);
    default:
      throw new Error(`${labelForFormat(format)} import is not available yet.`);
  }
}

export function labelForFormat(format: ExternalImportFormat): string {
  const option = EXTERNAL_IMPORT_OPTIONS.find((item) => item.format === format);
  return option === undefined ? format : option.label;
}

async function convertAndOtp(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  let cleartext = data;
  let cleartextIsOwned = false;
  if (!looksLikeJson(data)) {
    if (password.length === 0) {
      throw new ImportPasswordRequiredError();
    }
    if (data.length < 4 + 12 + 12 + 16) {
      throw new Error('The andOTP encrypted backup is incomplete.');
    }
    const iterations = readUint32(data, 0);
    if (iterations <= 0 || iterations > 10_000_000) {
      throw new Error('The andOTP backup contains an invalid iteration count.');
    }
    const salt = data.subarray(4, 16);
    const iv = data.subarray(16, 28);
    const key = await derivePbkdf2(password, salt, iterations, 32, 'SHA1');
    try {
      cleartext = await decryptAesGcm(key, iv, data.subarray(28), EMPTY_BYTES);
      cleartextIsOwned = true;
    } catch {
      throw new ImportPasswordRequiredError('The andOTP password is incorrect or the file is damaged.');
    } finally {
      key.fill(0);
    }
  }

  try {
    const rawTokens = parseJsonArray(cleartext, 'andOTP');
    const result = emptyImportResult();
    for (let index = 0; index < rawTokens.length; index++) {
      try {
        const token = asRecord(rawTokens[index]);
        const type = authenticatorType(token['type']);
        const account = createAuthenticator(type);
        const issuer = stringValue(token['issuer']).trim();
        const label = stringValue(token['label']).trim();
        account.issuer = issuer.length > 0 ? issuer : label;
        account.username = issuer.length > 0 ? label : '';
        account.secret = stringValue(token['secret']);
        account.digits = numberValue(token['digits'], account.digits);
        account.algorithm = otpAlgorithm(token['algorithm']);
        account.period = numberValue(token['period'], account.period);
        account.counter = numberValue(token['counter'], 0);
        const tags = token['tags'];
        const categoryName = Array.isArray(tags) && tags.length > 0 ? stringValue(tags[0]) : '';
        addImportedAuthenticator(result, account, categoryName);
      } catch (error) {
        result.failures.push(`Account ${index + 1}: ${errorText(error)}`);
      }
    }
    ensureImportHasAccounts(result);
    return result;
  } finally {
    if (cleartextIsOwned) {
      cleartext.fill(0);
    }
  }
}

async function convertFreeOtp(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  if (password.length === 0) {
    throw new ImportPasswordRequiredError();
  }
  const serialized = parseFreeOtpStringMap(data);
  const masterText = serialized.get('masterKey');
  if (masterText === undefined) {
    throw new Error('The FreeOTP backup does not contain its master key.');
  }
  const master = parseJsonRecord(masterText, 'FreeOTP master key');
  const algorithmName = stringValue(master['mAlgorithm']).toLocaleUpperCase();
  const hash: 'SHA1' | 'SHA512' = algorithmName.endsWith('SHA512') ? 'SHA512' : 'SHA1';
  const salt = BASE64.decodeSync(stringValue(master['mSalt']));
  const iterations = numberValue(master['mIterations'], 0);
  const wrappingKey = await derivePbkdf2(password, salt, iterations, 32, hash);
  salt.fill(0);
  const encryptedMaster = parseJsonRecord(stringValue(master['mEncryptedKey']), 'FreeOTP encrypted master key');
  let masterKey: Uint8Array;
  try {
    masterKey = await decryptFreeOtpValue(encryptedMaster, wrappingKey, stringValue(encryptedMaster['mToken']));
  } catch {
    throw new ImportPasswordRequiredError('The FreeOTP password is incorrect or the backup is damaged.');
  } finally {
    wrappingKey.fill(0);
  }

  const result = emptyImportResult();
  try {
    for (const tokenKey of serialized.keys()) {
      if (!tokenKey.endsWith('-token')) {
        continue;
      }
      try {
        const tokenText = serialized.get(tokenKey) ?? '';
        const token = parseJsonRecord(tokenText, 'FreeOTP token');
        const pairedText = serialized.get(tokenKey.substring(0, tokenKey.length - 6));
        if (pairedText === undefined) {
          throw new Error('The token does not have a matching encrypted key.');
        }
        const paired = parseJsonRecord(pairedText, 'FreeOTP encrypted token key');
        const encryptedSecret = parseJsonRecord(stringValue(paired['key']), 'FreeOTP encrypted secret');
        const secretBytes = await decryptFreeOtpValue(encryptedSecret, masterKey, stringValue(token['mToken']));
        try {
          const textSecret = TEXT_DECODER.decodeToString(secretBytes).trim();
          const secret = /^[A-Z2-7]+=*$/i.test(textSecret) ? textSecret : base32Encode(secretBytes);
          const type = authenticatorType(token['type'] ?? token['mType']);
          const account = createAuthenticator(type);
          const issuer = stringValue(token['issuer'] ?? token['mIssuer']).trim();
          const label = stringValue(token['label'] ?? token['mLabel']).trim();
          account.issuer = issuer.length > 0 ? issuer : label;
          account.username = issuer.length > 0 ? label : '';
          account.secret = secret;
          account.algorithm = otpAlgorithm(token['algorithm'] ?? token['mAlgorithm']);
          account.digits = numberValue(token['digits'] ?? token['mDigits'], account.digits);
          account.period = numberValue(token['period'] ?? token['mPeriod'], account.period);
          account.counter = numberValue(token['counter'] ?? token['mCounter'], 0);
          addImportedAuthenticator(result, account);
        } finally {
          secretBytes.fill(0);
        }
      } catch (error) {
        result.failures.push(`${tokenKey}: ${errorText(error)}`);
      }
    }
  } finally {
    masterKey.fill(0);
  }
  ensureImportHasAccounts(result);
  return result;
}

async function convertWinAuth(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  const uriList = await readWinAuthZip(data, password);
  try {
    return convertUriList(uriList);
  } finally {
    uriList.fill(0);
  }
}

interface WinAuthEntry {
  flags: number;
  method: number;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
  dosTime: number;
}

async function readWinAuthZip(data: Uint8Array, password: string): Promise<Uint8Array> {
  const eocd = findZipEnd(data);
  const entryCount = readLittleEndian16(data, eocd + 10);
  let directoryOffset = readLittleEndian32(data, eocd + 16);
  for (let index = 0; index < entryCount; index++) {
    if (readLittleEndian32(data, directoryOffset) !== 0x02014b50) {
      throw new Error('The WinAuth ZIP file contains an invalid directory entry.');
    }
    const entry: WinAuthEntry = {
      flags: readLittleEndian16(data, directoryOffset + 8),
      method: readLittleEndian16(data, directoryOffset + 10),
      dosTime: readLittleEndian16(data, directoryOffset + 12),
      crc: readLittleEndian32(data, directoryOffset + 16),
      compressedSize: readLittleEndian32(data, directoryOffset + 20),
      uncompressedSize: readLittleEndian32(data, directoryOffset + 24),
      localOffset: readLittleEndian32(data, directoryOffset + 42)
    };
    const filenameLength = readLittleEndian16(data, directoryOffset + 28);
    const extraLength = readLittleEndian16(data, directoryOffset + 30);
    const commentLength = readLittleEndian16(data, directoryOffset + 32);
    const filenameOffset = directoryOffset + 46;
    const filename = TEXT_DECODER.decodeToString(data.subarray(filenameOffset, filenameOffset + filenameLength));
    directoryOffset = filenameOffset + filenameLength + extraLength + commentLength;
    if (filename.endsWith('/')) {
      continue;
    }
    if (entry.uncompressedSize > 16 * 1024 * 1024 ||
      entry.localOffset + 30 > data.length || entry.compressedSize > data.length) {
      throw new Error('The WinAuth ZIP entry is too large or truncated.');
    }
    if (readLittleEndian32(data, entry.localOffset) !== 0x04034b50) {
      throw new Error('The WinAuth ZIP file contains an invalid local header.');
    }
    const localNameLength = readLittleEndian16(data, entry.localOffset + 26);
    const localExtraLength = readLittleEndian16(data, entry.localOffset + 28);
    const compressedOffset = entry.localOffset + 30 + localNameLength + localExtraLength;
    if (compressedOffset + entry.compressedSize > data.length) {
      throw new Error('The WinAuth ZIP entry is truncated.');
    }
    let compressed = data.subarray(compressedOffset, compressedOffset + entry.compressedSize);
    const encryptedEntry = (entry.flags & 1) !== 0;
    if (encryptedEntry) {
      if (password.length === 0) {
        throw new ImportPasswordRequiredError();
      }
      const checkByte = (entry.flags & 8) !== 0 ? (entry.dosTime >>> 8) & 0xff : (entry.crc >>> 24) & 0xff;
      compressed = decryptZipCrypto(compressed, password, checkByte);
    }
    let cleartext: Uint8Array;
    if (entry.method === 0) {
      cleartext = compressed.slice();
    } else if (entry.method === 8) {
      cleartext = await inflateRaw(compressed, entry.uncompressedSize);
    } else {
      throw new Error(`The WinAuth ZIP uses unsupported compression method ${entry.method}.`);
    }
    if (cleartext.length !== entry.uncompressedSize || crc32(cleartext) !== entry.crc) {
      cleartext.fill(0);
      throw new Error('The WinAuth ZIP entry failed its integrity check.');
    }
    if (encryptedEntry) {
      compressed.fill(0);
    }
    return cleartext;
  }
  throw new Error('The WinAuth ZIP does not contain a backup file.');
}

function findZipEnd(data: Uint8Array): number {
  const minimum = Math.max(0, data.length - 65557);
  for (let index = data.length - 22; index >= minimum; index--) {
    if (readLittleEndian32(data, index) === 0x06054b50) {
      return index;
    }
  }
  throw new Error('The selected file is not a valid WinAuth ZIP backup.');
}

async function inflateRaw(data: Uint8Array, outputLength: number): Promise<Uint8Array> {
  const cleartext = decompressRawDeflate(data);
  if (cleartext.length !== outputLength) {
    cleartext.fill(0);
    throw new Error('The WinAuth ZIP entry could not be decompressed.');
  }
  return cleartext;
}

function decryptZipCrypto(encrypted: Uint8Array, password: string, checkByte: number): Uint8Array {
  if (encrypted.length < 12) {
    throw new Error('The encrypted WinAuth ZIP entry is incomplete.');
  }
  const keys = new Uint32Array([0x12345678, 0x23456789, 0x34567890]);
  const passwordBytes = utf8Bytes(password);
  for (const byte of passwordBytes) {
    updateZipCryptoKeys(keys, byte);
  }
  const plain = new Uint8Array(encrypted.length - 12);
  let headerCheck = 0;
  for (let index = 0; index < 12; index++) {
    headerCheck = decryptZipCryptoByte(keys, encrypted[index]);
  }
  if (headerCheck !== checkByte) {
    passwordBytes.fill(0);
    throw new ImportPasswordRequiredError('The WinAuth ZIP password is incorrect.');
  }
  for (let index = 12; index < encrypted.length; index++) {
    plain[index - 12] = decryptZipCryptoByte(keys, encrypted[index]);
  }
  passwordBytes.fill(0);
  return plain;
}

function decryptZipCryptoByte(keys: Uint32Array, encryptedByte: number): number {
  const temporary = (keys[2] | 2) >>> 0;
  const plainByte = encryptedByte ^ ((Math.imul(temporary, temporary ^ 1) >>> 8) & 0xff);
  updateZipCryptoKeys(keys, plainByte);
  return plainByte;
}

function updateZipCryptoKeys(keys: Uint32Array, value: number): void {
  keys[0] = crc32Byte(keys[0], value);
  keys[1] = (Math.imul((keys[1] + (keys[0] & 0xff)) >>> 0, 134775813) + 1) >>> 0;
  keys[2] = crc32Byte(keys[2], keys[1] >>> 24);
}

function crc32Byte(crc: number, value: number): number {
  let updated = (crc ^ value) >>> 0;
  for (let bit = 0; bit < 8; bit++) {
    updated = (updated & 1) !== 0 ? ((updated >>> 1) ^ 0xedb88320) >>> 0 : updated >>> 1;
  }
  return updated;
}

function crc32(data: Uint8Array): number {
  let result = 0xffffffff;
  for (const value of data) {
    result = crc32Byte(result, value);
  }
  return (result ^ 0xffffffff) >>> 0;
}

function readLittleEndian16(data: Uint8Array, offset: number): number {
  const low = data[offset];
  const high = data[offset + 1];
  if (low === undefined || high === undefined) {
    throw new Error('The ZIP file is truncated.');
  }
  return low | (high << 8);
}

function readLittleEndian32(data: Uint8Array, offset: number): number {
  const byte0 = data[offset];
  const byte1 = data[offset + 1];
  const byte2 = data[offset + 2];
  const byte3 = data[offset + 3];
  if (byte0 === undefined || byte1 === undefined || byte2 === undefined || byte3 === undefined) {
    throw new Error('The ZIP file is truncated.');
  }
  return (byte0 | (byte1 << 8) | (byte2 << 16) | (byte3 << 24)) >>> 0;
}

async function convertKeePass(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  if (password.length === 0) {
    throw new ImportPasswordRequiredError();
  }
  kdbxweb.CryptoEngine.setArgon2Impl(ohosArgon2);
  const buffer = new ArrayBuffer(data.length);
  new Uint8Array(buffer).set(data);
  let database: kdbxweb.Kdbx;
  try {
    const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password));
    database = await kdbxweb.Kdbx.load(buffer, credentials);
  } catch {
    throw new ImportPasswordRequiredError('The KeePass password is incorrect or the database is damaged.');
  }

  const result = emptyImportResult();
  const recycleBinUuid = database.meta.recycleBinUuid;
  for (const entry of database.getDefaultGroup().allEntries()) {
    try {
      const parentName = entry.parentGroup?.name ?? '';
      if (parentName.toLocaleLowerCase() === 'history' ||
        parentName.toLocaleLowerCase() === 'recycle bin' ||
        entry.parentGroup?.uuid.equals(recycleBinUuid)) {
        continue;
      }
      const value = entry.fields.get('otp');
      const uri = value instanceof kdbxweb.ProtectedValue ? value.getText() :
        typeof value === 'string' ? value : '';
      if (!uri.startsWith('otpauth://') && !uri.startsWith('motp://')) {
        continue;
      }
      const parsed = parseOtpUri(uri);
      if (parsed.pinRequiredLength > 0) {
        result.failures.push(`${parsed.authenticator.issuer}: a PIN is required.`);
        continue;
      }
      addImportedAuthenticator(result, parsed.authenticator, parentName);
    } catch (error) {
      result.failures.push(`Entry: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

async function decryptFreeOtpValue(value: Record<string, Object>, key: Uint8Array,
  associatedData: string): Promise<Uint8Array> {
  const cipherName = stringValue(value['mCipher']).toLocaleUpperCase();
  if (!cipherName.includes('GCM')) {
    throw new Error(`Unsupported FreeOTP cipher: ${cipherName}.`);
  }
  const parameters = parseFreeOtpParameters(stringValue(value['mParameters']));
  const encrypted = BASE64.decodeSync(stringValue(value['mCipherText']));
  if (encrypted.length < parameters.macLength) {
    throw new Error('The FreeOTP encrypted value is incomplete.');
  }
  const ciphertext = encrypted.subarray(0, encrypted.length - parameters.macLength);
  const tag = encrypted.subarray(encrypted.length - parameters.macLength);
  try {
    return await decryptAesGcm(key, parameters.iv, ciphertext, tag,
      utf8Bytes(associatedData));
  } finally {
    encrypted.fill(0);
  }
}

function parseFreeOtpParameters(value: string): FreeOtpParameters {
  const data = BASE64.decodeSync(value);
  const cursor: DerCursor = { offset: 0 };
  if (data[cursor.offset] !== 0x30) {
    throw new Error('The FreeOTP cipher parameters are not a DER sequence.');
  }
  cursor.offset++;
  const sequenceLength = readDerLength(data, cursor);
  if (cursor.offset + sequenceLength > data.length || data[cursor.offset] !== 0x04) {
    throw new Error('The FreeOTP cipher parameters contain an invalid IV.');
  }
  cursor.offset++;
  const ivLength = readDerLength(data, cursor);
  const iv = data.subarray(cursor.offset, cursor.offset + ivLength);
  cursor.offset += ivLength;
  if (data[cursor.offset] !== 0x02) {
    throw new Error('The FreeOTP cipher parameters contain an invalid MAC length.');
  }
  cursor.offset++;
  const integerLength = readDerLength(data, cursor);
  if (integerLength < 1 || integerLength > 4 || cursor.offset + integerLength > data.length) {
    throw new Error('The FreeOTP cipher parameters contain an invalid MAC length.');
  }
  let macBits = 0;
  for (let index = 0; index < integerLength; index++) {
    macBits = (macBits * 256) + data[cursor.offset + index];
  }
  const tagLength = macBits / 8;
  if (!Number.isInteger(tagLength) || tagLength < 4 || tagLength > 16) {
    throw new Error('The FreeOTP cipher parameters specify an unsupported MAC length.');
  }
  return { iv, macLength: tagLength };
}

function parseFreeOtpStringMap(data: Uint8Array): Map<string, string> {
  const values: Array<string> = [];
  let offset = 0;
  while (offset < data.length) {
    const tag = data[offset];
    if (tag === 0x74) {
      if (offset + 3 > data.length) {
        throw new Error('The FreeOTP serialized backup is truncated.');
      }
      const length = (data[offset + 1] << 8) | data[offset + 2];
      offset += 3;
      if (offset + length > data.length) {
        throw new Error('The FreeOTP serialized string is truncated.');
      }
      values.push(decodeModifiedUtf8(data.subarray(offset, offset + length)));
      offset += length;
    } else if (tag === 0x77) {
      if (offset + 2 > data.length) {
        throw new Error('The FreeOTP serialized backup is truncated.');
      }
      offset += 2 + data[offset + 1];
    } else if (tag === 0x7a) {
      if (offset + 5 > data.length) {
        throw new Error('The FreeOTP serialized backup is truncated.');
      }
      const length = readUint32(data, offset + 1);
      offset += 5 + length;
    } else if (tag === 0x7c) {
      if (offset + 9 > data.length) {
        throw new Error('The FreeOTP serialized backup is truncated.');
      }
      const length = readUint32(data, offset + 5);
      offset += 9 + length;
    } else {
      offset++;
    }
  }
  if (values.length < 2) {
    throw new Error('The selected file is not a supported FreeOTP backup.');
  }
  const entries = new Map<string, string>();
  for (let index = 0; index + 1 < values.length; index += 2) {
    entries.set(values[index], values[index + 1]);
  }
  return entries;
}

function decodeModifiedUtf8(data: Uint8Array): string {
  let result = '';
  for (let index = 0; index < data.length;) {
    const first = data[index];
    if (first < 0x80) {
      result += String.fromCharCode(first);
      index++;
    } else if ((first & 0xe0) === 0xc0 && index + 1 < data.length) {
      result += String.fromCharCode(((first & 0x1f) << 6) | (data[index + 1] & 0x3f));
      index += 2;
    } else if ((first & 0xf0) === 0xe0 && index + 2 < data.length) {
      result += String.fromCharCode(((first & 0x0f) << 12) | ((data[index + 1] & 0x3f) << 6) |
        (data[index + 2] & 0x3f));
      index += 3;
    } else {
      throw new Error('The FreeOTP backup contains an invalid Java UTF string.');
    }
  }
  return result;
}

function parseJsonRecord(value: string, name: string): Record<string, Object> {
  const parsed = JSON.parse(value) as Object;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`The ${name} is invalid.`);
  }
  return parsed as Record<string, Object>;
}

function readDerLength(data: Uint8Array, cursor: DerCursor): number {
  const first = data[cursor.offset];
  if (first === undefined) {
    throw new Error('The FreeOTP DER parameters are truncated.');
  }
  cursor.offset++;
  if ((first & 0x80) === 0) {
    return first;
  }
  const byteCount = first & 0x7f;
  if (byteCount < 1 || byteCount > 4 || cursor.offset + byteCount > data.length) {
    throw new Error('The FreeOTP DER parameters contain an invalid length.');
  }
  let length = 0;
  for (let index = 0; index < byteCount; index++) {
    length = length * 256 + data[cursor.offset + index];
  }
  cursor.offset += byteCount;
  return length;
}

async function convertAegis(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  const root = parseJsonObject(data, 'Aegis');
  if (numberValue(root['version'], 0) !== 1) {
    throw new Error('This Aegis backup version is not supported.');
  }
  let database: Record<string, Object>;
  const rawDatabase = root['db'];
  if (typeof rawDatabase === 'string') {
    if (password.length === 0) {
      throw new ImportPasswordRequiredError();
    }
    database = await decryptAegisDatabase(root, rawDatabase, password);
  } else {
    database = asRecord(rawDatabase);
  }
  const rawEntries = database['entries'];
  if (!Array.isArray(rawEntries)) {
    throw new Error('The Aegis backup does not contain an entry list.');
  }
  const result = emptyImportResult();
  for (let index = 0; index < rawEntries.length; index++) {
    try {
      const entry = asRecord(rawEntries[index]);
      const info = asRecord(entry['info']);
      const type = aegisAuthenticatorType(entry['type']);
      const account = createAuthenticator(type);
      const name = stringValue(entry['name']).trim();
      const issuer = stringValue(entry['issuer']).trim();
      account.issuer = issuer.length > 0 ? issuer : name;
      account.username = issuer.length > 0 ? name : '';
      const secret = stringValue(info['secret']);
      account.secret = type === 'mOTP' ? bytesToHex(toBase32Bytes(secret)) : secret;
      account.algorithm = aegisAlgorithm(info['algo'], type);
      account.digits = numberValue(info['digits'], account.digits);
      account.period = numberValue(info['period'], account.period);
      account.counter = numberValue(info['counter'], 0);
      account.pin = stringValue(info['pin']);
      account.icon = stringValue(entry['icon']);
      addImportedAuthenticator(result, account, stringValue(entry['group']));
    } catch (error) {
      result.failures.push(`Entry ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

async function decryptAegisDatabase(root: Record<string, Object>, encryptedDatabase: string,
  password: string): Promise<Record<string, Object>> {
  const header = asRecord(root['header']);
  const headerParams = asRecord(header['params']);
  const slots = header['slots'];
  if (!Array.isArray(slots)) {
    throw new Error('The Aegis backup does not contain password slots.');
  }
  const slot = (slots as Array<Object>).map((value) => asRecord(value))
    .find((value) => {
      const type = stringValue(value['type']).toLocaleLowerCase();
      return type === '1' || type === 'password';
    });
  if (slot === undefined) {
    throw new Error('The Aegis backup does not contain a password slot.');
  }
  const keyParams = asRecord(slot['key_params']);
  const salt = decodeHex(stringValue(slot['salt']));
  const scryptKey = await deriveScrypt(password, salt, numberValue(slot['n'], 0),
    numberValue(slot['r'], 0), numberValue(slot['p'], 0), 32);
  let masterKey: Uint8Array;
  try {
    masterKey = await decryptAesGcm(scryptKey, decodeHex(stringValue(keyParams['nonce'])),
      decodeHex(stringValue(slot['key'])), decodeHex(stringValue(keyParams['tag'])));
  } catch {
    throw new ImportPasswordRequiredError('The Aegis password is incorrect or the file is damaged.');
  } finally {
    scryptKey.fill(0);
  }
  try {
    const cleartext = await decryptAesGcm(masterKey, decodeHex(stringValue(headerParams['nonce'])),
      BASE64.decodeSync(encryptedDatabase), decodeHex(stringValue(headerParams['tag'])));
    try {
      const parsed = JSON.parse(TEXT_DECODER.decodeToString(cleartext)) as Object;
      return asRecord(parsed);
    } finally {
      cleartext.fill(0);
    }
  } catch (error) {
    if (error instanceof ImportPasswordRequiredError) {
      throw error;
    }
    throw new ImportPasswordRequiredError('The Aegis password is incorrect or the backup is damaged.');
  } finally {
    masterKey.fill(0);
  }
}

async function convertTwoFas(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  const root = parseJsonObject(data, '2FAS');
  let rawServices = root['services'];
  if (typeof root['servicesEncrypted'] === 'string') {
    if (password.length === 0) {
      throw new ImportPasswordRequiredError();
    }
    const parts = stringValue(root['servicesEncrypted']).split(':');
    if (parts.length !== 3) {
      throw new Error('The encrypted 2FAS backup has an invalid format.');
    }
    const ciphertext = BASE64.decodeSync(parts[0]);
    const salt = BASE64.decodeSync(parts[1]);
    const iv = BASE64.decodeSync(parts[2]);
    const key = await derivePbkdf2(password, salt, 10_000, 32, 'SHA256');
    let cleartext: Uint8Array;
    try {
      cleartext = await decryptAesGcm(key, iv, ciphertext, EMPTY_BYTES);
    } catch {
      throw new ImportPasswordRequiredError('The 2FAS password is incorrect or the file is damaged.');
    } finally {
      key.fill(0);
    }
    try {
      rawServices = JSON.parse(TEXT_DECODER.decodeToString(cleartext)) as Object;
    } finally {
      cleartext.fill(0);
    }
  }
  if (!Array.isArray(rawServices)) {
    throw new Error('The 2FAS backup does not contain a service list.');
  }
  const groups = new Map<string, string>();
  const rawGroups = root['groups'];
  if (Array.isArray(rawGroups)) {
    for (const rawGroup of rawGroups as Array<Object>) {
      const group = asRecord(rawGroup);
      const id = stringValue(group['id']);
      const name = stringValue(group['name']).trim();
      if (id.length > 0 && name.length > 0) {
        groups.set(id, name);
      }
    }
  }
  const result = emptyImportResult();
  for (let index = 0; index < rawServices.length; index++) {
    try {
      const service = asRecord(rawServices[index]);
      const otp = asRecord(service['otp']);
      const type = authenticatorType(otp['tokenType']);
      const account = createAuthenticator(type);
      const issuer = stringValue(otp['issuer']).trim();
      const username = stringValue(otp['account']).trim();
      const serviceName = stringValue(service['name']).trim();
      account.issuer = issuer.length > 0 ? issuer : username.length > 0 ? username : serviceName;
      account.username = issuer.length > 0 ? username : '';
      account.secret = stringValue(service['secret']);
      account.algorithm = otpAlgorithm(otp['algorithm']);
      const digits = numberValue(otp['digits'], account.digits);
      const period = numberValue(otp['period'], account.period);
      account.digits = digits > 0 ? digits : account.digits;
      account.period = period > 0 ? period : account.period;
      account.counter = numberValue(otp['counter'], 0);
      const group = groups.get(stringValue(service['groupId'])) ?? '';
      addImportedAuthenticator(result, account, group);
    } catch (error) {
      result.failures.push(`Service ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

async function convertTotpAuthenticator(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  if (password.length === 0) {
    throw new ImportPasswordRequiredError();
  }
  const encoded = TEXT_DECODER.decodeToString(data).trim();
  const encrypted = BASE64.decodeSync(encoded);
  const key = sha256(utf8Bytes(password)) as Uint8Array;
  let cleartext: Uint8Array;
  try {
    cleartext = await decryptAesCbc(key, new Uint8Array(16), encrypted);
  } catch {
    throw new ImportPasswordRequiredError('The TOTP Authenticator password is incorrect or the file is damaged.');
  } finally {
    key.fill(0);
    encrypted.fill(0);
  }
  let text = TEXT_DECODER.decodeToString(cleartext);
  cleartext.fill(0);
  if (text.length < 2) {
    throw new Error('The TOTP Authenticator backup is incomplete.');
  }
  text = text.substring(2);
  const lastArrayEnd = text.lastIndexOf(']');
  if (lastArrayEnd < 0) {
    throw new Error('The TOTP Authenticator backup does not contain an account list.');
  }
  text = text.substring(0, lastArrayEnd + 1).replace(/\\"/g, '"');
  const parsed = JSON.parse(text) as Object;
  if (!Array.isArray(parsed)) {
    throw new Error('The TOTP Authenticator backup does not contain an account list.');
  }
  const result = emptyImportResult();
  const accounts = parsed as Array<Object>;
  for (let index = 0; index < accounts.length; index++) {
    try {
      const source = asRecord(accounts[index]);
      if (numberValue(source['base'], 16) !== 16) {
        throw new Error('Only hexadecimal secrets are supported.');
      }
      const account = createAuthenticator('TOTP');
      const name = stringValue(source['name']).trim();
      const issuer = stringValue(source['issuer']).trim();
      account.issuer = issuer.length > 0 ? issuer : name;
      account.username = issuer.length > 0 ? name : '';
      account.secret = base32Encode(decodeHex(stringValue(source['key'])));
      account.digits = numberValue(source['digits'], 6);
      account.period = numberValue(source['period'], 30);
      addImportedAuthenticator(result, account);
    } catch (error) {
      result.failures.push(`Account ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

async function convertAuthenticatorPlus(data: Uint8Array, password: string,
  context: common.Context): Promise<ExternalImportResult> {
  if (password.length === 0) {
    throw new ImportPasswordRequiredError();
  }
  const fileName = `authenticator-plus-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}.db`;
  const databaseDirectory = `${context.databaseDir}/rdb`;
  if (!fileIo.accessSync(databaseDirectory)) {
    fileIo.mkdirSync(databaseDirectory);
  }
  const databasePath = `${databaseDirectory}/${fileName}`;
  let temporaryFileCreated = false;
  try {
    const file = fileIo.openSync(databasePath,
      fileIo.OpenMode.CREATE | fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.TRUNC);
    temporaryFileCreated = true;
    try {
      const buffer = new ArrayBuffer(data.length);
      new Uint8Array(buffer).set(data);
      const bytesWritten = fileIo.writeSync(file.fd, buffer);
      if (bytesWritten !== data.length) {
        throw new Error('The Authenticator Plus database could not be copied completely.');
      }
    } finally {
      fileIo.closeSync(file);
    }
  } catch (error) {
    if (temporaryFileCreated) {
      fileIo.unlinkSync(databasePath);
    }
    if (error instanceof Error) {
      throw error;
    }
    throw new Error(errorText(error));
  }

  let store: relationalStore.RdbStore | null = null;
  const passwordBytes = utf8Bytes(password);
  try {
    const cryptoParam: relationalStore.CryptoParam = {
      encryptionKey: passwordBytes,
      iterationCount: 64000,
      encryptionAlgo: relationalStore.EncryptionAlgo.AES_256_CBC,
      hmacAlgo: relationalStore.HmacAlgo.SHA1,
      kdfAlgo: relationalStore.KdfAlgo.KDF_SHA1,
      cryptoPageSize: 1024
    };
    const config: relationalStore.StoreConfig = {
      name: fileName,
      securityLevel: relationalStore.SecurityLevel.S1,
      encrypt: true,
      cryptoParam
    };
    store = await relationalStore.getRdbStore(context, config);
    const categories = new Map<string, string>();
    const categoryRows = await store.querySql('SELECT name FROM category');
    try {
      const nameIndex = categoryRows.getColumnIndex('name');
      while (categoryRows.goToNextRow()) {
        const name = categoryRows.getString(nameIndex).trim();
        if (name.length > 0) {
          categories.set(name.toLocaleLowerCase(), name);
        }
      }
    } finally {
      categoryRows.close();
    }

    const rows = await store.querySql('SELECT email, secret, counter, type, issuer, original_name, category FROM accounts');
    const result = emptyImportResult();
    try {
      const emailIndex = rows.getColumnIndex('email');
      const secretIndex = rows.getColumnIndex('secret');
      const counterIndex = rows.getColumnIndex('counter');
      const typeIndex = rows.getColumnIndex('type');
      const issuerIndex = rows.getColumnIndex('issuer');
      const originalNameIndex = rows.getColumnIndex('original_name');
      const categoryIndex = rows.getColumnIndex('category');
      let rowNumber = 0;
      while (rows.goToNextRow()) {
        rowNumber++;
        try {
          const typeValue = rows.getLong(typeIndex);
          const type: AuthenticatorType = typeValue === 1 ? 'HOTP' : 'TOTP';
          const account = createAuthenticator(type);
          const originalName = readColumnString(rows, originalNameIndex);
          const email = readColumnString(rows, emailIndex);
          const issuer = readColumnString(rows, issuerIndex);
          account.issuer = typeValue === 2 ? 'Blizzard' :
            issuer.trim().length > 0 ? issuer : originalName.trim().length > 0 ? originalName : email;
          account.username = typeValue === 2 ? '' : issuer.trim().length > 0 ? email : '';
          const secret = readColumnString(rows, secretIndex);
          account.secret = typeValue === 2 ? base32Encode(decodeHex(secret)) : secret;
          account.counter = Math.max(0, rows.getLong(counterIndex));
          if (typeValue === 2) {
            account.digits = 8;
          }
          const categoryValue = readColumnString(rows, categoryIndex).trim();
          const category = categories.get(categoryValue.toLocaleLowerCase()) ?? '';
          addImportedAuthenticator(result, account,
            category === 'All Accounts' ? '' : category);
        } catch (error) {
          result.failures.push(`Account ${rowNumber}: ${errorText(error)}`);
        }
      }
    } finally {
      rows.close();
    }
    ensureImportHasAccounts(result);
    return result;
  } catch (error) {
    if (error instanceof ImportPasswordRequiredError) {
      throw error;
    }
    if (store === null) {
      throw new ImportPasswordRequiredError(
        `The Authenticator Plus password is incorrect or the database format is unsupported: ${errorText(error)}`);
    }
    throw new Error(`The Authenticator Plus database could not be read: ${errorText(error)}`);
  } finally {
    try {
      await store?.close();
    } finally {
      passwordBytes.fill(0);
      for (const temporaryPath of [databasePath, `${databasePath}-wal`, `${databasePath}-shm`]) {
        if (fileIo.accessSync(temporaryPath)) {
          fileIo.unlinkSync(temporaryPath);
        }
      }
    }
  }
}

function readColumnString(rows: relationalStore.ResultSet, index: number): string {
  return index < 0 ? '' : rows.getString(index);
}

function convertUriList(data: Uint8Array): ExternalImportResult {
  const result = emptyImportResult();
  const lines = TEXT_DECODER.decodeToString(data).replace(/^\uFEFF/, '').split(/\r?\n/);
  for (let index = 0; index < lines.length; index++) {
    const uri = lines[index].trim();
    if (uri.length === 0) {
      continue;
    }
    if (!uri.startsWith('otpauth://') && !uri.startsWith('motp://')) {
      throw new Error(`Line ${index + 1} is not an OTP URI.`);
    }
    try {
      const parsed = parseOtpUri(uri);
      if (parsed.pinRequiredLength > 0) {
        throw new Error(`This entry requires a ${parsed.pinRequiredLength}-character PIN.`);
      }
      addImportedAuthenticator(result, parsed.authenticator);
    } catch (error) {
      result.failures.push(`Line ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

function convertFreeOtpPlus(data: Uint8Array): ExternalImportResult {
  const root = parseJsonObject(data, 'FreeOTP+');
  const rawTokens = root['tokens'];
  if (!Array.isArray(rawTokens)) {
    throw new Error('The FreeOTP+ backup does not contain a token list.');
  }
  const result = emptyImportResult();
  for (let index = 0; index < rawTokens.length; index++) {
    try {
      const token = asRecord(rawTokens[index]);
      const secretValue = token['secret'];
      const secret = Array.isArray(secretValue)
        ? base32Encode(new Uint8Array(secretValue.map((value: number) => value & 0xff)))
        : stringValue(secretValue);
      const type = authenticatorType(token['type']);
      if (type !== 'TOTP' && type !== 'HOTP') {
        throw new Error('Unsupported token type.');
      }
      const tokenIssuer = stringValue(token['issuerExt']).trim();
      const label = stringValue(token['label']).trim();
      const account = createAuthenticator(type);
      account.issuer = tokenIssuer.length > 0 ? tokenIssuer : label;
      account.username = tokenIssuer.length > 0 ? label : '';
      account.secret = secret;
      account.algorithm = otpAlgorithm(token['algo']);
      account.digits = numberValue(token['digits'], account.digits);
      account.period = numberValue(token['period'], account.period);
      account.counter = numberValue(token['counter'], 0);
      addImportedAuthenticator(result, account);
    } catch (error) {
      result.failures.push(`Token ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

function convertProton(data: Uint8Array): ExternalImportResult {
  const root = parseJsonObject(data, 'Proton Authenticator');
  if (numberValue(root['version'], 0) !== 1 || !Array.isArray(root['entries'])) {
    throw new Error('The Proton Authenticator backup format is unsupported.');
  }
  const result = emptyImportResult();
  const entries = root['entries'] as Array<Object>;
  for (let index = 0; index < entries.length; index++) {
    try {
      const entry = asRecord(entries[index]);
      const content = asRecord(entry['content']);
      const entryType = stringValue(content['entry_type']);
      const uri = stringValue(content['uri']);
      if (entryType !== 'Totp' && entryType !== 'Steam') {
        throw new Error(`Unsupported Proton entry type: ${entryType}.`);
      }
      const name = stringValue(content['name']).trim();
      let account: AuthenticatorRecord;
      if (entryType === 'Steam' && uri.toLocaleLowerCase().startsWith('steam://')) {
        account = createAuthenticator('Steam');
        account.secret = uri.substring('steam://'.length);
        account.issuer = name.length > 0 ? name : 'Steam';
      } else {
        account = parseOtpUri(uri).authenticator;
        if (name.length > 0 && name !== account.username) {
          account.username = name.substring(0, 40);
        }
      }
      addImportedAuthenticator(result, account);
    } catch (error) {
      result.failures.push(`Entry ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

function convertLastPass(data: Uint8Array): ExternalImportResult {
  const root = parseJsonObject(data, 'LastPass Authenticator');
  if (numberValue(root['version'], 0) !== 3 || !Array.isArray(root['accounts'])) {
    throw new Error('The LastPass Authenticator backup format is unsupported.');
  }
  const result = emptyImportResult();
  const folderNames = new Map<string, string>();
  const rawFolders = root['folders'];
  if (Array.isArray(rawFolders)) {
    for (const rawFolder of rawFolders as Array<Object>) {
      const folder = asRecord(rawFolder);
      const id = stringValue(folder['id']);
      const name = stringValue(folder['name']).trim();
      if (id.length > 0 && name.length > 0) {
        folderNames.set(id, name);
      }
    }
  }
  const accounts = root['accounts'] as Array<Object>;
  for (let index = 0; index < accounts.length; index++) {
    try {
      const account = asRecord(accounts[index]);
      const item = createAuthenticator('TOTP');
      const username = stringValue(account['userName']).trim();
      const issuer = stringValue(account['issuerName']).trim();
      item.issuer = issuer.length > 0 ? issuer : username;
      item.username = issuer.length > 0 ? username : '';
      item.secret = stringValue(account['secret']);
      item.period = numberValue(account['timeStep'], 30);
      item.digits = numberValue(account['digits'], 6);
      item.algorithm = otpAlgorithm(account['algorithm']);
      const folderData = asRecord(account['folderData']);
      const folderName = folderNames.get(stringValue(folderData['folderId']));
      addImportedAuthenticator(result, item, folderName ?? '');
    } catch (error) {
      result.failures.push(`Account ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

async function convertBitwarden(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  let root = parseJsonObject(data, 'Bitwarden');
  if (root['encrypted'] === true) {
    if (root['passwordProtected'] !== true) {
      throw new Error('Bitwarden account-restricted exports are not supported.');
    }
    if (password.length === 0) {
      throw new ImportPasswordRequiredError();
    }
    const saltText = stringValue(root['salt']);
    const saltBytes = utf8Bytes(saltText);
    const kdfType = numberValue(root['kdfType'], -1);
    let key: Uint8Array;
    if (kdfType === 0) {
      key = await derivePbkdf2(password, saltBytes, numberValue(root['kdfIterations'], 0), 32, 'SHA256');
    } else if (kdfType === 1) {
      const salt = sha256(saltBytes) as Uint8Array;
      key = await deriveArgon2id(password, salt, numberValue(root['kdfIterations'], 0),
        numberValue(root['kdfMemory'], 64) * 1024, numberValue(root['kdfParallelism'], 4));
      salt.fill(0);
    } else {
      throw new Error('This Bitwarden key-derivation mode is not supported.');
    }
    try {
      const dataField = stringValue(root['data']);
      const separator = dataField.indexOf('.');
      if (separator <= 0) {
        throw new Error('The encrypted Bitwarden export has an invalid data field.');
      }
      const parts = dataField.substring(separator + 1).split('|');
      if (parts.length !== 3) {
        throw new Error('The encrypted Bitwarden export has an invalid data field.');
      }
      const iv = BASE64.decodeSync(parts[0]);
      const ciphertext = BASE64.decodeSync(parts[1]);
      const expectedMac = BASE64.decodeSync(parts[2]);
      const encKey = hkdf(sha256, key, undefined, utf8Bytes('enc'), 32) as Uint8Array;
      const macKey = hkdf(sha256, key, undefined, utf8Bytes('mac'), 32) as Uint8Array;
      const actualMac = hmac(sha256, macKey, concatBytes(iv, ciphertext)) as Uint8Array;
      if (!constantTimeEqual(actualMac, expectedMac)) {
        throw new ImportPasswordRequiredError('The Bitwarden password is incorrect or the export is damaged.');
      }
      const cleartext = await decryptAesCbc(encKey, iv, ciphertext);
      try {
        root = parseJsonObject(cleartext, 'Bitwarden decrypted');
      } finally {
        cleartext.fill(0);
        encKey.fill(0);
        macKey.fill(0);
        actualMac.fill(0);
        expectedMac.fill(0);
      }
    } catch (error) {
      if (error instanceof ImportPasswordRequiredError) {
        throw error;
      }
      throw new ImportPasswordRequiredError('The Bitwarden password is incorrect or the export is damaged.');
    } finally {
      key.fill(0);
      saltBytes.fill(0);
    }
  }
  return convertBitwardenVault(root);
}

function convertBitwardenVault(root: Record<string, Object>): ExternalImportResult {
  const rawItems = root['items'];
  if (!Array.isArray(rawItems)) {
    throw new Error('The Bitwarden export does not contain a vault item list.');
  }
  const folders = new Map<string, string>();
  const rawFolders = root['folders'];
  if (Array.isArray(rawFolders)) {
    for (const rawFolder of rawFolders as Array<Object>) {
      const folder = asRecord(rawFolder);
      const id = stringValue(folder['id']);
      const name = stringValue(folder['name']).trim();
      if (id.length > 0 && name.length > 0) {
        folders.set(id, name);
      }
    }
  }
  const result = emptyImportResult();
  const items = rawItems as Array<Object>;
  for (let index = 0; index < items.length; index++) {
    try {
      const item = asRecord(items[index]);
      const itemType = stringValue(item['type']).toLocaleLowerCase();
      if (itemType !== '1' && itemType !== 'login') {
        continue;
      }
      const login = asRecord(item['login']);
      const totp = stringValue(login['totp']);
      if (totp.length === 0) {
        continue;
      }
      let account: AuthenticatorRecord;
      if (totp.toLocaleLowerCase().startsWith('otpauth://')) {
        account = parseOtpUri(totp).authenticator;
      } else if (totp.toLocaleLowerCase().startsWith('steam://')) {
        account = createAuthenticator('Steam');
        account.secret = totp.substring('steam://'.length);
      } else {
        account = createAuthenticator('TOTP');
        account.secret = totp;
      }
      const name = stringValue(item['name']).trim();
      const username = stringValue(login['username']).trim();
      if (name.length > 0) {
        account.issuer = name;
      }
      if (username.length > 0) {
        account.username = username;
      }
      addImportedAuthenticator(result, account, folders.get(stringValue(item['folderId'])) ?? '');
    } catch (error) {
      result.failures.push(`Item ${index + 1}: ${errorText(error)}`);
    }
  }
  ensureImportHasAccounts(result);
  return result;
}

async function convertEnte(data: Uint8Array, password: string): Promise<ExternalImportResult> {
  if (!looksLikeJson(data)) {
    return convertUriList(data);
  }
  const root = parseJsonObject(data, 'Ente Auth');
  if (numberValue(root['version'], 0) !== 1) {
    throw new Error('This Ente Auth backup version is not supported.');
  }
  if (password.length === 0) {
    throw new ImportPasswordRequiredError();
  }
  const kdfParams = asRecord(root['kdfParams']);
  const salt = BASE64.decodeSync(stringValue(kdfParams['salt']));
  const memLimit = numberValue(kdfParams['memLimit'], 0);
  const opsLimit = numberValue(kdfParams['opsLimit'], 0);
  const memoryKiB = Math.floor(memLimit / 1024);
  let key: Uint8Array;
  try {
    key = await deriveArgon2id(password, salt, opsLimit, memoryKiB, 1);
  } finally {
    salt.fill(0);
  }
  let cleartext: Uint8Array;
  try {
    const nonce = BASE64.decodeSync(stringValue(root['encryptionNonce']));
    const encrypted = BASE64.decodeSync(stringValue(root['encryptedData']));
    cleartext = await decryptXChaCha20Poly1305(key, nonce, encrypted);
  } catch {
    key.fill(0);
    throw new ImportPasswordRequiredError('The Ente Auth password is incorrect or the backup is damaged.');
  }
  key.fill(0);
  try {
    return convertUriList(utf8Bytes(TEXT_DECODER.decodeToString(cleartext)));
  } finally {
    cleartext.fill(0);
  }
}

function emptyImportResult(): ExternalImportResult {
  return { vault: emptyVault(), failures: [] };
}

function addImportedAuthenticator(result: ExternalImportResult, account: AuthenticatorRecord,
  categoryName: string = ''): void {
  const issuer = account.issuer.trim();
  account.issuer = issuer.substring(0, 32);
  account.username = account.username.trim().substring(0, 40);
  if (account.icon.length === 0) {
    account.icon = iconKeyForIssuer(account.issuer);
  }
  if (categoryName.trim().length > 0) {
    const name = categoryName.trim();
    let category = result.vault.categories.find((item) => item.name.toLocaleLowerCase() === name.toLocaleLowerCase());
    if (category === undefined) {
      category = { id: categoryIdForName(name), name, ranking: result.vault.categories.length };
      result.vault.categories.push(category);
    }
    account.categoryId = category.id;
  }
  account.ranking = result.vault.authenticators.length;
  result.vault.authenticators.push(validateAuthenticator(account));
}

function ensureImportHasAccounts(result: ExternalImportResult): void {
  if (result.vault.authenticators.length === 0) {
    if (result.failures.length > 0) {
      throw new Error(result.failures.join('\n'));
    }
    throw new Error('The selected file does not contain supported authenticator accounts.');
  }
}

function parseJsonObject(data: Uint8Array, name: string): Record<string, Object> {
  const parsed = JSON.parse(TEXT_DECODER.decodeToString(data)) as Object;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`The ${name} backup is not a JSON object.`);
  }
  return parsed as Record<string, Object>;
}

function asRecord(value: Object | undefined): Record<string, Object> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('The backup contains an invalid entry.');
  }
  return value as Record<string, Object>;
}

function stringValue(value: Object | undefined): string {
  return value === undefined || value === null ? '' : String(value);
}

function numberValue(value: Object | undefined, defaultValue: number): number {
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }
  const result = Number(value);
  return Number.isFinite(result) ? result : defaultValue;
}

function authenticatorType(value: Object | undefined): AuthenticatorType {
  const type = String(value).toLocaleUpperCase();
  if (type === 'HOTP') {
    return 'HOTP';
  }
  if (type === 'TOTP') {
    return 'TOTP';
  }
  if (type === 'STEAM') {
    return 'Steam';
  }
  throw new Error(`Unsupported authenticator type: ${type}.`);
}

function otpAlgorithm(value: Object | undefined): OtpAlgorithm {
  const rawAlgorithm = stringValue(value).trim();
  if (rawAlgorithm.length === 0) {
    return 'SHA1';
  }
  const algorithm = rawAlgorithm.toLocaleUpperCase().replace(/[-_]/g, '');
  if (algorithm === 'SHA256') {
    return 'SHA256';
  }
  if (algorithm === 'SHA512') {
    return 'SHA512';
  }
  if (algorithm === 'SHA1') {
    return 'SHA1';
  }
  throw new Error(`Unsupported OTP hash algorithm: ${rawAlgorithm}.`);
}

function base32Encode(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let accumulator = 0;
  let bitCount = 0;
  let result = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      result += alphabet.charAt((accumulator >> bitCount) & 0x1f);
    }
  }
  if (bitCount > 0) {
    result += alphabet.charAt((accumulator << (5 - bitCount)) & 0x1f);
  }
  return result;
}

function looksLikeJson(data: Uint8Array): boolean {
  let index = 0;
  if (data.length >= 3 && data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) {
    index = 3;
  }
  while (index < data.length) {
    const byte = data[index];
    if (byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d) {
      index++;
    } else {
      return byte === 0x7b || byte === 0x5b;
    }
  }
  return false;
}

function readUint32(data: Uint8Array, offset: number): number {
  const first = data[offset];
  const second = data[offset + 1];
  const third = data[offset + 2];
  const fourth = data[offset + 3];
  if (first === undefined || second === undefined || third === undefined || fourth === undefined) {
    throw new Error('The encrypted backup header is incomplete.');
  }
  return first * 0x1000000 + second * 0x10000 + third * 0x100 + fourth;
}

function parseJsonArray(data: Uint8Array, name: string): Array<Object> {
  const parsed = JSON.parse(TEXT_DECODER.decodeToString(data)) as Object;
  if (!Array.isArray(parsed)) {
    throw new Error(`The ${name} backup does not contain a token list.`);
  }
  return parsed as Array<Object>;
}

async function derivePbkdf2(password: string, salt: Uint8Array, iterations: number, keySize: number,
  hash: 'SHA1' | 'SHA256' | 'SHA512'): Promise<Uint8Array> {
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 10_000_000 ||
    !Number.isInteger(keySize) || keySize < 1 || keySize > 64) {
    throw new Error('The backup contains unsafe key derivation parameters.');
  }
  const kdf = cryptoFramework.createKdf(`PBKDF2|${hash}`);
  const spec: cryptoFramework.PBKDF2Spec = {
    algName: 'PBKDF2',
    password,
    salt,
    iterations,
    keySize
  };
  const result = await kdf.generateSecret(spec);
  return result.data;
}

@Concurrent
function deriveImportArgon2Task(passwordBuffer: ArrayBuffer, saltBuffer: ArrayBuffer, iterations: number,
  memoryKiB: number, parallelism: number): ArrayBuffer {
  const passwordBytes = new Uint8Array(passwordBuffer);
  const saltBytes = new Uint8Array(saltBuffer);
  let derivedKey: Uint8Array | undefined;
  try {
    const options: ArgonOpts = {
      t: iterations,
      m: memoryKiB,
      p: parallelism,
      dkLen: 32
    };
    derivedKey = argon2id(passwordBytes, saltBytes, options) as Uint8Array;
    const result = new Uint8Array(derivedKey.length);
    result.set(derivedKey);
    return result.buffer as ArrayBuffer;
  } finally {
    passwordBytes.fill(0);
    saltBytes.fill(0);
    derivedKey?.fill(0);
  }
}

async function deriveArgon2id(password: string, salt: Uint8Array, iterations: number,
  memoryKiB: number, parallelism: number): Promise<Uint8Array> {
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 10 ||
    !Number.isInteger(memoryKiB) || memoryKiB < 8 || memoryKiB > 512 * 1024 ||
    !Number.isInteger(parallelism) || parallelism < 1 || parallelism > 16) {
    throw new Error('The backup contains unsafe Argon2id parameters.');
  }
  const passwordBytes = utf8Bytes(password);
  const passwordBuffer = new ArrayBuffer(passwordBytes.length);
  const saltBuffer = new ArrayBuffer(salt.length);
  new Uint8Array(passwordBuffer).set(passwordBytes);
  new Uint8Array(saltBuffer).set(salt);
  let result: Object | undefined;
  try {
    result = await taskpool.execute(deriveImportArgon2Task, passwordBuffer, saltBuffer,
      iterations, memoryKiB, parallelism);
  } finally {
    passwordBytes.fill(0);
  }
  if (!(result instanceof ArrayBuffer) || result.byteLength !== 32) {
    throw new Error('Argon2id returned an invalid import key.');
  }
  return new Uint8Array(result);
}

async function deriveScrypt(password: string, salt: Uint8Array, n: number, r: number,
  p: number, keySize: number): Promise<Uint8Array> {
  if (!Number.isInteger(n) || n < 1024 || n > 262144 || (n & (n - 1)) !== 0 ||
    !Number.isInteger(r) || r < 1 || r > 32 || !Number.isInteger(p) || p < 1 || p > 16) {
    throw new Error('The Aegis backup contains unsafe scrypt parameters.');
  }
  const maxMemory = Math.min(256 * 1024 * 1024, Math.max(32 * 1024 * 1024, n * r * 256));
  const kdf = cryptoFramework.createKdf('SCRYPT');
  const spec: cryptoFramework.ScryptSpec = {
    algName: 'SCRYPT',
    passphrase: password,
    salt,
    n,
    r,
    p,
    maxMemory,
    keySize
  };
  const result = await kdf.generateSecret(spec);
  return result.data;
}

async function decryptAesGcm(keyBytes: Uint8Array, iv: Uint8Array, encrypted: Uint8Array,
  providedTag: Uint8Array, aad: Uint8Array = EMPTY_BYTES): Promise<Uint8Array> {
  if (iv.length < 12 || keyBytes.length !== 32) {
    throw new Error('The encrypted backup contains invalid AES-GCM parameters.');
  }
  const ciphertext = providedTag.length > 0
    ? encrypted
    : encrypted.subarray(0, encrypted.length - 16);
  const tag = providedTag.length > 0
    ? providedTag
    : encrypted.subarray(encrypted.length - 16);
  if (tag.length < 4 || tag.length > 16 || (tag.length !== 4 && tag.length !== 8 && tag.length < 12)) {
    throw new Error('The encrypted backup is incomplete.');
  }
  const generator = cryptoFramework.createSymKeyGenerator('AES256');
  const key = await generator.convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|GCM|NoPadding');
  const params: cryptoFramework.GcmParamsSpec = {
    algName: 'GcmParamsSpec',
    iv: { data: iv },
    aad: { data: aad },
    authTag: { data: tag }
  };
  await cipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, key, params);
  const result = await cipher.doFinal({ data: ciphertext });
  return result.data;
}

async function decryptAesCbc(keyBytes: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (keyBytes.length !== 32 || iv.length !== 16 || ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new Error('The encrypted backup contains invalid AES-CBC parameters.');
  }
  const generator = cryptoFramework.createSymKeyGenerator('AES256');
  const key = await generator.convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|CBC|PKCS7');
  const params: cryptoFramework.IvParamsSpec = {
    algName: 'IvParamsSpec',
    iv: { data: iv }
  };
  await cipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, key, params);
  return (await cipher.doFinal({ data: ciphertext })).data;
}

async function decryptXChaCha20Poly1305(keyBytes: Uint8Array, nonce: Uint8Array,
  encrypted: Uint8Array): Promise<Uint8Array> {
  if (keyBytes.length !== 32 || nonce.length !== 24 || encrypted.length < 16) {
    throw new Error('The Ente Auth backup contains invalid XChaCha20 parameters.');
  }
  return xchacha20poly1305(keyBytes, nonce).decrypt(encrypted);
}

function decodeHex(value: string): Uint8Array {
  const text = value.trim().replace(/^0x/i, '');
  if (text.length === 0 || text.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(text)) {
    throw new Error('The backup contains invalid hexadecimal data.');
  }
  const result = new Uint8Array(text.length / 2);
  for (let index = 0; index < result.length; index++) {
    result[index] = Number.parseInt(text.substring(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function bytesToHex(data: Uint8Array): string {
  let result = '';
  for (const byte of data) {
    result += byte.toString(16).padStart(2, '0');
  }
  return result;
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function aegisAuthenticatorType(value: Object | undefined): AuthenticatorType {
  const type = String(value).toLocaleLowerCase();
  if (type === 'totp') return 'TOTP';
  if (type === 'hotp') return 'HOTP';
  if (type === 'steam') return 'Steam';
  if (type === 'motp') return 'mOTP';
  if (type === 'yandex') return 'Yandex';
  throw new Error(`Unsupported Aegis authenticator type: ${type}.`);
}

function aegisAlgorithm(value: Object | undefined, type: AuthenticatorType): OtpAlgorithm {
  const algorithm = stringValue(value).toLocaleUpperCase();
  if (algorithm === 'MD5' && type === 'mOTP') {
    return 'SHA1';
  }
  if (algorithm === 'SHA1' || algorithm === 'SHA256' || algorithm === 'SHA512') {
    return algorithm;
  }
  throw new Error(`Unsupported Aegis hash algorithm: ${algorithm}.`);
}

function errorText(error: Object): string {
  return error instanceof Error && error.message.length > 0 ? error.message : 'Unsupported authenticator entry.';
}
