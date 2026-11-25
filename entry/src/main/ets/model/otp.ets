import { hmac } from '@noble/hashes/hmac.js';
import { md5, sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import util from '@ohos.util';

const TEXT_ENCODER = new util.TextEncoder();

export type AuthenticatorType = 'TOTP' | 'HOTP' | 'mOTP' | 'Steam' | 'Yandex';
export type OtpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface AuthenticatorRecord {
  id: string;
  type: AuthenticatorType;
  issuer: string;
  username: string;
  secret: string;
  pin: string;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter: number;
  icon: string;
  categoryId: string;
  ranking: number;
  copyCount: number;
}

export interface AuthenticatorPatch {
  type?: AuthenticatorType;
  issuer?: string;
  username?: string;
  secret?: string;
  pin?: string;
  algorithm?: OtpAlgorithm;
  digits?: number;
  period?: number;
  counter?: number;
  icon?: string;
  categoryId?: string;
  ranking?: number;
  copyCount?: number;
}

export interface AuthenticatorCategory {
  id: string;
  name: string;
  ranking: number;
}

export interface CustomIcon {
  id: string;
  data: string;
}

export interface VaultData {
  authenticators: Array<AuthenticatorRecord>;
  categories: Array<AuthenticatorCategory>;
  customIcons: Array<CustomIcon>;
}

export interface ParsedOtpUri {
  authenticator: AuthenticatorRecord;
  pinRequiredLength: number;
}

export function emptyVault(): VaultData {
  return {
    authenticators: [],
    categories: [],
    customIcons: []
  };
}

export function utf8Bytes(value: string): Uint8Array {
  return TEXT_ENCODER.encodeInto(value);
}

export function categoryIdForName(name: string): string {
  return bytesToHex(sha1(utf8Bytes(name)) as Uint8Array).substring(0, 8);
}

export function copyAuthenticator(record: AuthenticatorRecord): AuthenticatorRecord {
  const copied: AuthenticatorRecord = {
    id: record.id,
    type: record.type,
    issuer: record.issuer,
    username: record.username,
    secret: record.secret,
    pin: record.pin,
    algorithm: record.algorithm,
    digits: record.digits,
    period: record.period,
    counter: record.counter,
    icon: record.icon,
    categoryId: record.categoryId,
    ranking: record.ranking,
    copyCount: record.copyCount
  };
  return copied;
}

export function patchAuthenticator(record: AuthenticatorRecord, patch: AuthenticatorPatch): AuthenticatorRecord {
  const updated = copyAuthenticator(record);
  if (patch.type !== undefined) updated.type = patch.type;
  if (patch.issuer !== undefined) updated.issuer = patch.issuer;
  if (patch.username !== undefined) updated.username = patch.username;
  if (patch.secret !== undefined) updated.secret = patch.secret;
  if (patch.pin !== undefined) updated.pin = patch.pin;
  if (patch.algorithm !== undefined) updated.algorithm = patch.algorithm;
  if (patch.digits !== undefined) updated.digits = patch.digits;
  if (patch.period !== undefined) updated.period = patch.period;
  if (patch.counter !== undefined) updated.counter = patch.counter;
  if (patch.icon !== undefined) updated.icon = patch.icon;
  if (patch.categoryId !== undefined) updated.categoryId = patch.categoryId;
  if (patch.ranking !== undefined) updated.ranking = patch.ranking;
  if (patch.copyCount !== undefined) updated.copyCount = patch.copyCount;
  return updated;
}

export function copyVault(
  vault: VaultData,
  authenticators: Array<AuthenticatorRecord> = vault.authenticators,
  categories: Array<AuthenticatorCategory> = vault.categories
): VaultData {
  const copiedIcons: Array<CustomIcon> = [];
  for (const icon of vault.customIcons) {
    const copy: CustomIcon = { id: icon.id, data: icon.data };
    copiedIcons.push(copy);
  }
  const result: VaultData = {
    authenticators,
    categories,
    customIcons: copiedIcons
  };
  return result;
}

export function mergeVaults(existing: VaultData, imported: VaultData): VaultData {
  const categories: Array<AuthenticatorCategory> = [];
  for (const category of existing.categories) {
    const copy: AuthenticatorCategory = {
      id: category.id,
      name: category.name,
      ranking: category.ranking
    };
    categories.push(copy);
  }
  const importedCategoryIds = new Map<string, string>();
  for (const category of imported.categories) {
    const id = category.id.trim();
    const name = category.name.trim();
    if (id.length === 0 || name.length === 0) {
      throw new Error('The imported backup contains an invalid category.');
    }

    let matching = categories.find((item: AuthenticatorCategory) => item.id === id);
    if (matching === undefined) {
      const normalizedName = name.toLocaleLowerCase();
      matching = categories.find((item: AuthenticatorCategory) =>
        item.name.toLocaleLowerCase() === normalizedName);
    }
    if (matching !== undefined) {
      importedCategoryIds.set(id, matching.id);
    } else {
      const added: AuthenticatorCategory = { id, name, ranking: categories.length };
      categories.push(added);
      importedCategoryIds.set(id, id);
    }
  }

  const authenticators = existing.authenticators.map((item: AuthenticatorRecord) => copyAuthenticator(item));
  const indexBySecret = new Map<string, number>();
  let nextRanking = 0;
  for (let index = 0; index < authenticators.length; index++) {
    const item = authenticators[index];
    if (item !== undefined) {
      indexBySecret.set(item.secret, index);
      nextRanking = Math.max(nextRanking, item.ranking + 1);
    }
  }

  for (const item of imported.authenticators) {
    const incoming = copyAuthenticator(item);
    if (incoming.categoryId.length > 0) {
      const mappedCategoryId = importedCategoryIds.get(incoming.categoryId);
      if (mappedCategoryId === undefined) {
        throw new Error('The imported backup refers to a category that was not imported.');
      }
      incoming.categoryId = mappedCategoryId;
    }

    const existingIndex = indexBySecret.get(incoming.secret);
    if (existingIndex !== undefined) {
      const current = authenticators[existingIndex];
      if (current === undefined) {
        throw new Error('The local authenticator list is inconsistent.');
      }
      incoming.id = current.id;
      incoming.ranking = current.ranking;
      if (incoming.categoryId.length === 0) {
        incoming.categoryId = current.categoryId;
      }
      authenticators[existingIndex] = incoming;
    } else {
      incoming.ranking = nextRanking;
      nextRanking++;
      indexBySecret.set(incoming.secret, authenticators.length);
      authenticators.push(incoming);
    }
  }

  const customIcons: Array<CustomIcon> = [];
  const customIconIds = new Set<string>();
  for (const icon of existing.customIcons) {
    const copy: CustomIcon = { id: icon.id, data: icon.data };
    customIcons.push(copy);
    customIconIds.add(icon.id);
  }
  for (const icon of imported.customIcons) {
    if (!customIconIds.has(icon.id)) {
      const copy: CustomIcon = { id: icon.id, data: icon.data };
      customIcons.push(copy);
      customIconIds.add(icon.id);
    }
  }

  return { authenticators, categories, customIcons };
}

export function createAuthenticator(type: AuthenticatorType = 'TOTP'): AuthenticatorRecord {
  return {
    id: `${Date.now()}-${Math.floor(Math.random() * 1000000)}`,
    type,
    issuer: '',
    username: '',
    secret: '',
    pin: '',
    algorithm: 'SHA1',
    digits: defaultDigits(type),
    period: 30,
    counter: 0,
    icon: '',
    categoryId: '',
    ranking: 0,
    copyCount: 0
  };
}

export function defaultDigits(type: AuthenticatorType): number {
  switch (type) {
    case 'Steam':
      return 5;
    case 'Yandex':
      return 8;
    default:
      return 6;
  }
}

export function authenticatorUri(record: AuthenticatorRecord): string {
  const issuer = record.issuer.trim();
  if (issuer.length === 0 || record.secret.length === 0) {
    throw new Error('An issuer and secret are required to create a QR code.');
  }
  if (record.type === 'mOTP') {
    return `motp://${issuer}:${record.username}?secret=${record.secret}`;
  }

  const scheme = record.type === 'HOTP' ? 'hotp' : record.type === 'Yandex' ? 'yaotp' : 'totp';
  const label = record.username.length > 0 ? `${issuer}:${record.username}` : issuer;
  const parameters = [`secret=${record.secret}`, `issuer=${encodeURIComponent(issuer)}`];
  if (record.algorithm !== 'SHA1') {
    parameters.push(`algorithm=${record.algorithm}`);
  }
  if (record.digits !== defaultDigits(record.type)) {
    parameters.push(`digits=${record.digits}`);
  }
  if (record.type === 'TOTP' && record.period !== 30) {
    parameters.push(`period=${record.period}`);
  } else if (record.type === 'HOTP') {
    parameters.push(`counter=${record.counter}`);
  } else if (record.type === 'Steam' && issuer !== 'Steam') {
    parameters.push('steam');
  } else if (record.type === 'Yandex' && record.pin.length > 0) {
    parameters.push(`pin_length=${record.pin.length}`);
  }
  return `otpauth://${scheme}/${encodeURIComponent(label)}?${parameters.join('&')}`;
}

export function validateAuthenticator(record: AuthenticatorRecord): AuthenticatorRecord {
  const issuer = record.issuer.trim();
  const username = record.username.trim();
  const secret = normaliseSecret(record.type, record.secret);
  const pin = record.pin.trim();

  if (issuer.length === 0 || issuer.length > 32) {
    throw new Error('Issuer is required and must be 32 characters or fewer.');
  }
  if (username.length > 40) {
    throw new Error('Account name must be 40 characters or fewer.');
  }
  if (record.type === 'TOTP' && (record.digits < 6 || record.digits > 10)) {
    throw new Error('TOTP codes must contain 6 to 10 digits.');
  }
  if (record.type === 'HOTP' && (record.digits < 6 || record.digits > 8)) {
    throw new Error('HOTP codes must contain 6 to 8 digits.');
  }
  if (record.type === 'TOTP' && (!Number.isInteger(record.period) || record.period <= 0)) {
    throw new Error('The time period must be a positive whole number.');
  }
  if (record.type === 'mOTP' && pin.length !== 4) {
    throw new Error('mOTP requires a 4-character PIN.');
  }
  if (record.type === 'Yandex' && (pin.length < 4 || pin.length > 16)) {
    throw new Error('Yandex PINs must contain 4 to 16 characters.');
  }
  if (!Number.isInteger(record.counter) || record.counter < 0) {
    throw new Error('The counter must be a non-negative whole number.');
  }

  const validated = copyAuthenticator(record);
  validated.issuer = issuer;
  validated.username = username;
  validated.secret = secret;
  validated.pin = pin;
  if (record.type !== 'TOTP' && record.type !== 'HOTP') {
    validated.algorithm = 'SHA1';
  }
  return validated;
}

export function normaliseSecret(type: AuthenticatorType, secret: string): string {
  const value = secret.trim().replace(/[\s-]/g, '');
  if (type === 'mOTP') {
    const normalised = value.toLowerCase();
    if (!/^[0-9a-f]{16,}$/.test(normalised)) {
      throw new Error('mOTP secrets must contain at least 16 hexadecimal characters.');
    }
    return normalised;
  }

  const normalised = value.toUpperCase().replace(/=+$/g, '');
  if (!/^[A-Z2-7]+$/.test(normalised)) {
    throw new Error('The secret must be a valid Base32 value.');
  }
  const decoded = decodeBase32(normalised);
  if (type === 'Yandex' && decoded.length < 16) {
    throw new Error('Yandex secrets must contain at least 16 bytes.');
  }
  if (decoded.length === 0) {
    throw new Error('The secret cannot be empty.');
  }
  return normalised;
}

export function parseOtpUri(input: string): ParsedOtpUri {
  const uri = input.trim();
  if (uri.toLowerCase().startsWith('motp://')) {
    const question = uri.indexOf('?');
    if (question < 0) {
      throw new Error('This mOTP URI is missing its secret.');
    }
    const label = decodeURIComponent(uri.substring(7, question));
    const separator = label.indexOf(':');
    if (separator <= 0) {
      throw new Error('This mOTP URI must contain an issuer and account name.');
    }
    const args = parseQuery(uri.substring(question + 1));
    const secret = args.get('secret');
    if (!secret) {
      throw new Error('This mOTP URI is missing its secret.');
    }
    const record = createAuthenticator('mOTP');
    record.issuer = label.substring(0, separator);
    record.username = label.substring(separator + 1);
    record.secret = normaliseSecret('mOTP', secret);
    return { authenticator: record, pinRequiredLength: 4 };
  }

  const prefix = 'otpauth://';
  if (!uri.toLowerCase().startsWith(prefix)) {
    throw new Error('Use an otpauth:// or motp:// URI.');
  }
  const content = uri.substring(prefix.length);
  const slash = content.indexOf('/');
  const question = content.indexOf('?');
  if (slash < 0 || question < slash) {
    throw new Error('This OTP URI is incomplete.');
  }
  const scheme = content.substring(0, slash).toLowerCase();
  const label = decodeURIComponent(content.substring(slash + 1, question)).replace(/\/+$/g, '');
  const args = parseQuery(content.substring(question + 1));

  let issuer = args.get('issuer') ?? '';
  let username = label;
  const labelSplit = label.indexOf(':');
  if (labelSplit >= 0) {
    const labelIssuer = label.substring(0, labelSplit);
    username = label.substring(labelSplit + 1);
    if (issuer.length === 0) {
      issuer = labelIssuer;
    }
  } else if (issuer.length > 0) {
    username = label;
  } else {
    issuer = label;
    username = '';
  }

  const isSteam = scheme === 'totp' &&
    (issuer.toLowerCase() === 'steam' || args.has('steam') || args.get('encoder') === 'steam');
  let type: AuthenticatorType;
  if (scheme === 'hotp') {
    type = 'HOTP';
  } else if (scheme === 'yaotp') {
    type = 'Yandex';
    issuer = 'Yandex';
  } else if (scheme === 'totp' && isSteam) {
    type = 'Steam';
    issuer = issuer || 'Steam';
  } else if (scheme === 'totp') {
    type = 'TOTP';
  } else {
    throw new Error('This OTP URI uses an unsupported code type.');
  }

  const secret = args.get('secret');
  if (!secret) {
    throw new Error('This OTP URI is missing its secret.');
  }
  const record = createAuthenticator(type);
  record.issuer = issuer;
  record.username = username;
  record.secret = normaliseSecret(type, secret);
  if (type === 'TOTP' || type === 'HOTP') {
    const algorithm = (args.get('algorithm') ?? 'SHA1').toUpperCase();
    if (algorithm !== 'SHA1' && algorithm !== 'SHA256' && algorithm !== 'SHA512') {
      throw new Error('This OTP URI uses an unsupported hash algorithm.');
    }
    record.algorithm = algorithm;
    record.digits = parsePositiveNumber(args.get('digits'), record.digits, 'digits');
  }
  if (type === 'TOTP') {
    record.period = parsePositiveNumber(args.get('period'), record.period, 'period');
  }
  if (type === 'HOTP') {
    record.counter = parseNonNegativeNumber(args.get('counter'), 0, 'counter');
  }
  const pinLength = type === 'Yandex'
    ? parsePositiveNumber(args.get('pin_length'), 0, 'PIN length')
    : 0;
  if (type === 'Yandex' && (pinLength < 4 || pinLength > 16)) {
    throw new Error('Yandex PIN length must be between 4 and 16.');
  }
  return { authenticator: record, pinRequiredLength: pinLength };
}

export function computeOtp(record: AuthenticatorRecord, nowSeconds: number = Math.floor(Date.now() / 1000)): string {
  const secret = normaliseSecret(record.type, record.secret);
  if (record.type === 'mOTP') {
    const timeOffset = Math.floor(nowSeconds / 30) * 30;
    return computeMotp(secret, record.pin, timeOffset);
  }

  if (record.type === 'Yandex') {
    const keyMaterial = decodeBase32(secret).slice(0, 16);
    const pinAndKey = concatBytes(utf8Bytes(record.pin), keyMaterial);
    const keyDigest = sha256(pinAndKey) as Uint8Array;
    const key = keyDigest[0] === 0 ? keyDigest.slice(1) : keyDigest;
    const digest = hmac(sha256, key, counterBytes(Math.floor(nowSeconds / 30))) as Uint8Array;
    const offset = digest[digest.length - 1] & 0x0f;
    let material = 0;
    const modulus = 208827064576;
    for (let index = 0; index < 8; index++) {
      const byte = index === 0 ? digest[offset] & 0x7f : digest[offset + index];
      material = (material * 256 + byte) % modulus;
    }
    return encodeAlphabet(material, 8, 'abcdefghijklmnopqrstuvwxyz');
  }

  const period = record.type === 'Steam' ? 30 : record.type === 'HOTP' ? 1 : record.period;
  const counter = record.type === 'HOTP'
    ? record.counter
    : Math.floor(nowSeconds / period);
  const secretBytes = decodeBase32(secret);
  const message = counterBytes(counter);
  const digest = hmacFor(record.algorithm, secretBytes, message);
  const offset = digest[digest.length - 1] & 0x0f;
  const material = ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  const positiveMaterial = material >>> 0;

  if (record.type === 'Steam') {
    return encodeAlphabet(positiveMaterial % 26, 5, '23456789BCDFGHJKMNPQRTVWXY', true, positiveMaterial);
  }
  return String(positiveMaterial % (10 ** record.digits)).padStart(record.digits, '0');
}

export function computeMotp(secret: string, pin: string, counter: number): string {
  const digest = md5(utf8Bytes(`${Math.floor(counter / 10)}${secret}${pin}`)) as Uint8Array;
  return bytesToHex(digest).substring(0, 6);
}

export function toBase32Bytes(secret: string): Uint8Array {
  return decodeBase32(secret);
}

function hmacFor(algorithm: OtpAlgorithm, key: Uint8Array, message: Uint8Array): Uint8Array {
  if (algorithm === 'SHA256') {
    return hmac(sha256, key, message) as Uint8Array;
  }
  if (algorithm === 'SHA512') {
    return hmac(sha512, key, message) as Uint8Array;
  }
  return hmac(sha1, key, message) as Uint8Array;
}

function decodeBase32(value: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes: Array<number> = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of value) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) {
      throw new Error('The secret must be a valid Base32 value.');
    }
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function counterBytes(counter: number): Uint8Array {
  if (!Number.isFinite(counter) || counter < 0 || !Number.isInteger(counter)) {
    throw new Error('The OTP counter is invalid.');
  }
  const bytes = new Uint8Array(8);
  let remaining = counter;
  for (let index = 7; index >= 0; index--) {
    bytes[index] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return bytes;
}

function encodeAlphabet(value: number, length: number, alphabet: string, steam: boolean = false,
  steamMaterial: number = value): string {
  let material = steam ? steamMaterial : value;
  let result = '';
  for (let index = 0; index < length; index++) {
    result += alphabet[material % alphabet.length];
    material = Math.floor(material / alphabet.length);
  }
  return steam ? result : result.split('').reverse().join('');
}

function bytesToHex(bytes: Uint8Array): string {
  let result = '';
  for (const byte of bytes) {
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

function parseQuery(raw: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const part of raw.split('&')) {
    if (part.length === 0) {
      continue;
    }
    const separator = part.indexOf('=');
    const key = decodeURIComponent((separator < 0 ? part : part.substring(0, separator)).replace(/\+/g, ' '));
    const value = separator < 0 ? '' : decodeURIComponent(part.substring(separator + 1).replace(/\+/g, ' '));
    values.set(key.toLowerCase(), value);
  }
  return values;
}

function parsePositiveNumber(value: string | undefined, defaultValue: number, name: string): number {
  if (value === undefined || value.length === 0) {
    return defaultValue;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`The ${name} value in this URI is invalid.`);
  }
  return parsed;
}

function parseNonNegativeNumber(value: string | undefined, defaultValue: number, name: string): number {
  if (value === undefined || value.length === 0) {
    return defaultValue;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`The ${name} value in this URI is invalid.`);
  }
  return parsed;
}
