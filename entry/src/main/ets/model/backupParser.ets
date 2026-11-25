import util from '@ohos.util';
import { AuthenticatorRecord, AuthenticatorType, emptyVault, OtpAlgorithm, validateAuthenticator, VaultData } from './otp';

interface BackupCategoryLink {
  categoryId: string;
  ranking: number;
}

export function parseAuthProBackup(cleartext: Uint8Array): VaultData {
  const text = new util.TextDecoder('utf-8').decodeToString(cleartext);
  const parsed = JSON.parse(text) as Record<string, Object>;
  const rawAuthenticators = parsed['Authenticators'];
  const rawCategories = parsed['Categories'];
  const rawAuthenticatorCategories = parsed['AuthenticatorCategories'];
  const rawCustomIcons = parsed['CustomIcons'];
  if (!Array.isArray(rawAuthenticators)) {
    throw new Error('The backup does not contain an authenticator list.');
  }

  const vault = emptyVault();
  const categoryLinks = new Map<string, BackupCategoryLink>();
  if (Array.isArray(rawAuthenticatorCategories)) {
    for (const value of rawAuthenticatorCategories as Array<Object>) {
      const rawLink = value as Record<string, Object>;
      const secret = stringValue(rawLink['AuthenticatorSecret']);
      categoryLinks.set(secret, {
        categoryId: stringValue(rawLink['CategoryId']),
        ranking: numberValue(rawLink['Ranking'], 0)
      });
    }
  }

  if (Array.isArray(rawCategories)) {
    for (const value of rawCategories as Array<Object>) {
      const item = value as Record<string, Object>;
      const name = stringValue(item['Name']).trim();
      const id = stringValue(item['Id']);
      if (name.length === 0 || id.length === 0) {
        throw new Error('The backup contains an invalid category.');
      }
      vault.categories.push({
        id,
        name,
        ranking: numberValue(item['Ranking'], vault.categories.length)
      });
    }
  }

  for (const value of rawAuthenticators as Array<Object>) {
    const item = value as Record<string, Object>;
    const record = authenticatorFromBackup(item);
    const category = categoryLinks.get(record.secret);
    if (category) {
      record.categoryId = category.categoryId;
      record.ranking = category.ranking;
    }
    vault.authenticators.push(validateAuthenticator(record));
  }
  const secrets = new Set<string>();
  for (const item of vault.authenticators) {
    if (secrets.has(item.secret)) {
      throw new Error('The backup contains duplicate authenticator secrets.');
    }
    secrets.add(item.secret);
    if (item.categoryId.length > 0 && !vault.categories.some((category) => category.id === item.categoryId)) {
      throw new Error('The backup references a category that does not exist.');
    }
  }

  if (Array.isArray(rawCustomIcons)) {
    for (const value of rawCustomIcons as Array<Object>) {
      const item = value as Record<string, Object>;
      vault.customIcons.push({
        id: stringValue(item['Id']),
        data: stringValue(item['Data'])
      });
    }
  }
  return vault;
}

function authenticatorFromBackup(item: Record<string, Object>): AuthenticatorRecord {
  const numericType = numberValue(item['Type'], 2);
  const type = typeFromNumber(numericType);
  const numericAlgorithm = numberValue(item['Algorithm'], 0);
  const algorithm = algorithmFromNumber(numericAlgorithm);
  return {
    id: `${Date.now()}-${Math.floor(Math.random() * 1000000)}`,
    type,
    icon: nullableString(item['Icon']),
    issuer: stringValue(item['Issuer']),
    username: nullableString(item['Username']),
    secret: stringValue(item['Secret']),
    pin: nullableString(item['Pin']),
    algorithm,
    digits: numberValue(item['Digits'], type === 'Steam' ? 5 : type === 'Yandex' ? 8 : 6),
    period: numberValue(item['Period'], 30),
    counter: numberValue(item['Counter'], 0),
    categoryId: '',
    ranking: numberValue(item['Ranking'], 0),
    copyCount: numberValue(item['CopyCount'], 0)
  };
}

function typeFromNumber(value: number): AuthenticatorType {
  switch (value) {
    case 1:
      return 'HOTP';
    case 2:
      return 'TOTP';
    case 3:
      return 'mOTP';
    case 4:
      return 'Steam';
    case 5:
      return 'Yandex';
    default:
      throw new Error('The backup contains an unsupported authenticator type.');
  }
}

function algorithmFromNumber(value: number): OtpAlgorithm {
  switch (value) {
    case 0:
      return 'SHA1';
    case 1:
      return 'SHA256';
    case 2:
      return 'SHA512';
    default:
      throw new Error('The backup contains an unsupported hash algorithm.');
  }
}

function stringValue(value: Object | undefined): string {
  if (value === undefined || value === null) {
    return '';
  }
  return String(value);
}

function nullableString(value: Object | undefined): string {
  return stringValue(value);
}

function numberValue(value: Object | undefined, defaultValue: number): number {
  if (value === undefined || value === null) {
    return defaultValue;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return defaultValue;
  }
  return parsed;
}
