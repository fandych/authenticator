import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { taskpool } from '@kit.ArkTS';
import util from '@ohos.util';
import { AuthenticatorCategory, AuthenticatorType, OtpAlgorithm, utf8Bytes, VaultData } from './otp';
import { parseAuthProBackup } from './backupParser';
import { ohosArgon2 } from 'kdbxweb/src/main/ets/crypto/argon2-rs';

const STRONG_HEADER = 'AUTHENTICATORPRO';
const LEGACY_HEADER = 'AuthenticatorPro';
const FUN_HEADER = 'FUNAUTHENTICATOR';
const FUN_BACKUP_FORMAT = 'fun-authenticator-backup';
const FUN_BACKUP_VERSION = 1;
const MAX_BACKUP_SIZE = 16 * 1024 * 1024;
const BACKGROUND_PARSE_THRESHOLD = 64 * 1024;

@Concurrent
function parseBackupTask(cleartextBuffer: ArrayBuffer): Object {
  const cleartext = new Uint8Array(cleartextBuffer);
  try {
    return parseAuthProBackup(cleartext);
  } finally {
    cleartext.fill(0);
  }
}

@Concurrent
function parseFunBackupTask(cleartextBuffer: ArrayBuffer): Object {
  const cleartext = new Uint8Array(cleartextBuffer);
  try {
    const format = 'fun-authenticator-backup';
    const version = 1;
    const parsed = JSON.parse(new util.TextDecoder('utf-8').decodeToString(cleartext)) as Record<string, Object>;
    if (parsed['format'] !== format || Number(parsed['version']) !== version) {
      throw new Error('The selected FUN backup has an unsupported format or version.');
    }
    const data = parsed['data'];
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      throw new Error('The selected FUN backup does not contain valid vault data.');
    }
    const vaultBytes = utf8Bytes(JSON.stringify(data));
    try {
      return parseAuthProBackup(vaultBytes);
    } finally {
      vaultBytes.fill(0);
    }
  } finally {
    cleartext.fill(0);
  }
}

interface BackupCustomIcon {
  Id: string;
  Data: string;
}

interface BackupAuthenticator {
  Type: number;
  Icon: string | null;
  Issuer: string;
  Username: string | null;
  Secret: string;
  Pin: string | null;
  Algorithm: number;
  Digits: number;
  Period: number;
  Counter: number;
  Ranking: number;
  CopyCount: number;
}

interface BackupCategory {
  Id: string;
  Name: string;
  Ranking: number;
}

interface BackupAuthenticatorCategory {
  CategoryId: string;
  AuthenticatorSecret: string;
  Ranking: number;
}

interface BackupDocument {
  Authenticators: Array<BackupAuthenticator>;
  Categories: Array<BackupCategory>;
  AuthenticatorCategories: Array<BackupAuthenticatorCategory>;
  CustomIcons: Array<BackupCustomIcon>;
}

interface FunBackupDocument {
  format: string;
  version: number;
  exportedAt: string;
  data: BackupDocument;
}

export async function decryptFunBackup(data: Uint8Array, password: string): Promise<VaultData> {
  if (data.length > MAX_BACKUP_SIZE) {
    throw new Error('The selected backup is too large.');
  }
  if (!hasPrefix(data, utf8Bytes(FUN_HEADER))) {
    return await decryptAuthPro(data, password);
  }
  if (password.length === 0) {
    throw new Error('Enter the backup password.');
  }
  if (data.length < FUN_HEADER.length + 16 + 12 + 16) {
    throw new Error('The selected FUN backup is incomplete.');
  }
  const salt = data.subarray(FUN_HEADER.length, FUN_HEADER.length + 16);
  const iv = data.subarray(FUN_HEADER.length + 16, FUN_HEADER.length + 28);
  const ciphertextAndTag = data.subarray(FUN_HEADER.length + 28);
  const ciphertext = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16);
  const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16);
  const key = await deriveStrongBackupKey(password, salt);
  let cleartext: Uint8Array | undefined;
  try {
    cleartext = await decryptGcm(key, iv, ciphertext, tag);
    return await parseFunBackupOffThread(cleartext);
  } finally {
    key.fill(0);
    cleartext?.fill(0);
  }
}

export async function encryptFunBackup(vault: VaultData, password: string): Promise<Uint8Array> {
  if (password.length === 0) {
    throw new Error('Enter a password for the backup.');
  }
  const document: FunBackupDocument = {
    format: FUN_BACKUP_FORMAT,
    version: FUN_BACKUP_VERSION,
    exportedAt: new Date().toISOString(),
    data: createBackupDocument(vault)
  };
  const cleartext = utf8Bytes(JSON.stringify(document));
  if (cleartext.length + FUN_HEADER.length + 16 + 12 + 16 > MAX_BACKUP_SIZE) {
    cleartext.fill(0);
    throw new Error('The FUN backup is too large to export.');
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveStrongBackupKey(password, salt);
  try {
    const encrypted = await encryptGcm(key, iv, cleartext);
    return concatBytes(utf8Bytes(FUN_HEADER), salt, iv, encrypted);
  } finally {
    key.fill(0);
    cleartext.fill(0);
  }
}

function parseFunBackup(cleartext: Uint8Array): VaultData {
  const parsed = JSON.parse(new util.TextDecoder('utf-8').decodeToString(cleartext)) as Record<string, Object>;
  if (parsed['format'] !== FUN_BACKUP_FORMAT || Number(parsed['version']) !== FUN_BACKUP_VERSION) {
    throw new Error('The selected FUN backup has an unsupported format or version.');
  }
  const data = parsed['data'];
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new Error('The selected FUN backup does not contain valid vault data.');
  }
  const vaultBytes = utf8Bytes(JSON.stringify(data));
  try {
    return parseAuthProBackup(vaultBytes);
  } finally {
    vaultBytes.fill(0);
  }
}

async function parseFunBackupOffThread(cleartext: Uint8Array): Promise<VaultData> {
  if (cleartext.length < BACKGROUND_PARSE_THRESHOLD) {
    return parseFunBackup(cleartext);
  }
  const buffer = new ArrayBuffer(cleartext.length);
  new Uint8Array(buffer).set(cleartext);
  const result: Object = await taskpool.execute(parseFunBackupTask, buffer);
  if (!isVaultData(result)) {
    throw new Error('The selected FUN backup could not be parsed.');
  }
  return result as VaultData;
}

export async function decryptAuthPro(data: Uint8Array, password: string): Promise<VaultData> {
  if (data.length > MAX_BACKUP_SIZE) {
    throw new Error('The selected backup is too large.');
  }
  const strongHeader = utf8Bytes(STRONG_HEADER);
  const legacyHeader = utf8Bytes(LEGACY_HEADER);
  if (hasPrefix(data, strongHeader)) {
    if (password.length === 0) {
      throw new Error('Enter the backup password.');
    }
    if (data.length < 16 + 16 + 12 + 16) {
      throw new Error('The selected strong backup is incomplete.');
    }
    const salt = data.subarray(16, 32);
    const iv = data.subarray(32, 44);
    const ciphertextAndTag = data.subarray(44);
    const ciphertext = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16);
    const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16);
    const key = await deriveStrongBackupKey(password, salt);
    let cleartext: Uint8Array | undefined;
    try {
      cleartext = await decryptGcm(key, iv, ciphertext, tag);
      return await parseBackupOffThread(cleartext);
    } finally {
      key.fill(0);
      cleartext?.fill(0);
    }
  }
  if (hasPrefix(data, legacyHeader)) {
    if (password.length === 0) {
      throw new Error('Enter the backup password.');
    }
    if (data.length < 16 + 20 + 16 + 16) {
      throw new Error('The selected legacy backup is incomplete.');
    }
    const salt = data.subarray(16, 36);
    const iv = data.subarray(36, 52);
    const ciphertext = data.subarray(52);
    const key = await deriveLegacyKey(password, salt);
    let cleartext: Uint8Array | undefined;
    try {
      cleartext = await decryptCbc(key, iv, ciphertext);
      return await parseBackupOffThread(cleartext);
    } finally {
      key.fill(0);
      cleartext?.fill(0);
    }
  }
  return await parseBackupOffThread(data);
}

async function parseBackupOffThread(cleartext: Uint8Array): Promise<VaultData> {
  if (cleartext.length < BACKGROUND_PARSE_THRESHOLD) {
    return parseAuthProBackup(cleartext);
  }
  const buffer = new ArrayBuffer(cleartext.length);
  new Uint8Array(buffer).set(cleartext);
  const result: Object = await taskpool.execute(parseBackupTask, buffer);
  if (!isVaultData(result)) {
    throw new Error('The selected backup could not be parsed.');
  }
  return result as VaultData;
}

function isVaultData(value: Object): boolean {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as Record<string, Object>;
  return Array.isArray(candidate['authenticators']) && Array.isArray(candidate['categories']) &&
    Array.isArray(candidate['customIcons']);
}

export async function encryptAuthPro(vault: VaultData, password: string): Promise<Uint8Array> {
  if (password.length === 0) {
    throw new Error('Enter a password for the backup.');
  }
  const document = createBackupDocument(vault);
  const cleartext = utf8Bytes(JSON.stringify(document));
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveStrongBackupKey(password, salt);
  try {
    const encrypted = await encryptGcm(key, iv, cleartext);
    return concatBytes(utf8Bytes(STRONG_HEADER), salt, iv, encrypted);
  } finally {
    key.fill(0);
    cleartext.fill(0);
  }
}

export async function encryptLegacyAuthPro(vault: VaultData, password: string): Promise<Uint8Array> {
  if (password.length === 0) {
    throw new Error('Enter a password for the backup.');
  }
  const document = createBackupDocument(vault);
  const cleartext = utf8Bytes(JSON.stringify(document));
  const salt = randomBytes(20);
  const iv = randomBytes(16);
  const key = await deriveLegacyKey(password, salt);
  try {
    const encrypted = await encryptCbc(key, iv, cleartext);
    return concatBytes(utf8Bytes(LEGACY_HEADER), salt, iv, encrypted);
  } finally {
    key.fill(0);
    cleartext.fill(0);
  }
}

function createBackupDocument(vault: VaultData): BackupDocument {
  const authenticators: Array<BackupAuthenticator> = [];
  for (const item of vault.authenticators) {
    const backupItem: BackupAuthenticator = {
      Type: numberForType(item.type),
      Icon: item.icon.length > 0 ? item.icon : null,
      Issuer: item.issuer,
      Username: item.username.length > 0 ? item.username : null,
      Secret: item.secret,
      Pin: item.pin.length > 0 ? item.pin : null,
      Algorithm: numberForAlgorithm(item.algorithm),
      Digits: item.digits,
      Period: item.period,
      Counter: item.counter,
      Ranking: item.ranking,
      CopyCount: item.copyCount
    };
    authenticators.push(backupItem);
  }
  const categories: Array<BackupCategory> = [];
  for (const item of vault.categories) {
    const backupCategory: BackupCategory = {
      Id: item.id,
      Name: item.name,
      Ranking: item.ranking
    };
    categories.push(backupCategory);
  }
  const categoryById = new Map<string, AuthenticatorCategory>();
  for (const category of vault.categories) {
    categoryById.set(category.id, category);
  }
  const authenticatorCategories: Array<BackupAuthenticatorCategory> = [];
  for (const item of vault.authenticators) {
    if (item.categoryId.length > 0 && categoryById.has(item.categoryId)) {
      const link: BackupAuthenticatorCategory = {
        CategoryId: item.categoryId,
        AuthenticatorSecret: item.secret,
        Ranking: item.ranking
      };
      authenticatorCategories.push(link);
    }
  }
  const customIcons: Array<BackupCustomIcon> = [];
  for (const item of vault.customIcons) {
    const icon: BackupCustomIcon = { Id: item.id, Data: item.data };
    customIcons.push(icon);
  }
  const document: BackupDocument = {
    Authenticators: authenticators,
    Categories: categories,
    AuthenticatorCategories: authenticatorCategories,
    CustomIcons: customIcons
  };
  return document;
}

async function deriveLegacyKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const kdf = cryptoFramework.createKdf('PBKDF2|SHA1');
  const spec: cryptoFramework.PBKDF2Spec = {
    algName: 'PBKDF2',
    password,
    salt,
    iterations: 64000,
    keySize: 32
  };
  const result = await kdf.generateSecret(spec);
  return result.data;
}

async function encryptGcm(keyBytes: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const keyGenerator = cryptoFramework.createSymKeyGenerator('AES256');
  const key = await keyGenerator.convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|GCM|NoPadding');
  const params: cryptoFramework.GcmParamsSpec = {
    algName: 'GcmParamsSpec',
    iv: { data: iv },
    aad: { data: new Uint8Array(0) },
    authTag: { data: new Uint8Array(0) }
  };
  await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, key, params);
  const result = await cipher.doFinal({ data: plaintext });
  return result.data;
}

async function decryptGcm(keyBytes: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array,
  tag: Uint8Array): Promise<Uint8Array> {
  const keyGenerator = cryptoFramework.createSymKeyGenerator('AES256');
  const key = await keyGenerator.convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|GCM|NoPadding');
  const params: cryptoFramework.GcmParamsSpec = {
    algName: 'GcmParamsSpec',
    iv: { data: iv },
    aad: { data: new Uint8Array(0) },
    authTag: { data: tag }
  };
  await cipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, key, params);
  try {
    const result = await cipher.doFinal({ data: ciphertext });
    return result.data;
  } catch {
    throw new Error('The password is incorrect or the backup is damaged.');
  }
}

async function encryptCbc(keyBytes: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const keyGenerator = cryptoFramework.createSymKeyGenerator('AES256');
  const key = await keyGenerator.convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|CBC|PKCS7');
  const params: cryptoFramework.IvParamsSpec = {
    algName: 'IvParamsSpec',
    iv: { data: iv }
  };
  await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, key, params);
  const result = await cipher.doFinal({ data: plaintext });
  return result.data;
}

async function decryptCbc(keyBytes: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const keyGenerator = cryptoFramework.createSymKeyGenerator('AES256');
  const key = await keyGenerator.convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|CBC|PKCS7');
  const params: cryptoFramework.IvParamsSpec = {
    algName: 'IvParamsSpec',
    iv: { data: iv }
  };
  await cipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, key, params);
  try {
    const result = await cipher.doFinal({ data: ciphertext });
    return result.data;
  } catch {
    throw new Error('The password is incorrect or the backup is damaged.');
  }
}

function randomBytes(length: number): Uint8Array {
  const result = cryptoFramework.createRandom().generateRandomSync(length);
  return result.data;
}

function numberForType(type: AuthenticatorType): number {
  switch (type) {
    case 'HOTP':
      return 1;
    case 'TOTP':
      return 2;
    case 'mOTP':
      return 3;
    case 'Steam':
      return 4;
    default:
      return 5;
  }
}

function numberForAlgorithm(algorithm: OtpAlgorithm): number {
  switch (algorithm) {
    case 'SHA256':
      return 1;
    case 'SHA512':
      return 2;
    default:
      return 0;
  }
}

async function deriveStrongBackupKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const passwordBytes = utf8Bytes(password);
  const passwordBuffer = new ArrayBuffer(passwordBytes.length);
  const saltBuffer = new ArrayBuffer(salt.length);
  new Uint8Array(passwordBuffer).set(passwordBytes);
  new Uint8Array(saltBuffer).set(salt);

  let result: ArrayBuffer;
  try {
    result = await ohosArgon2(passwordBuffer, saltBuffer, 65536, 3, 32, 4, 2, 0x13);
  } finally {
    passwordBytes.fill(0);
    new Uint8Array(passwordBuffer).fill(0);
    new Uint8Array(saltBuffer).fill(0);
  }
  if (result.byteLength !== 32) {
    throw new Error('Argon2id returned an invalid backup key.');
  }
  return new Uint8Array(result);
}

function hasPrefix(data: Uint8Array, prefix: Uint8Array): boolean {
  if (data.length < prefix.length) {
    return false;
  }
  for (let index = 0; index < prefix.length; index++) {
    if (data[index] !== prefix[index]) {
      return false;
    }
  }
  return true;
}

function concatBytes(...parts: Array<Uint8Array>): Uint8Array {
  let totalLength = 0;
  for (const part of parts) {
    totalLength += part.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

