import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { describe, it, expect } from '@ohos/hypium';
import { decryptAuthPro, encryptAuthPro, encryptLegacyAuthPro } from '../../../main/ets/model/backup';
import { parseGoogleMigrationUri } from '../../../main/ets/model/migration';
import { AuthenticatorCategory, AuthenticatorRecord, AuthenticatorType, authenticatorUri, computeMotp, computeOtp, createAuthenticator, CustomIcon, emptyVault, mergeVaults, parseOtpUri, utf8Bytes } from '../../../main/ets/model/otp';
import { parseStratumIconPack } from '../../../main/ets/model/iconpack';
import { DEFAULT_ICON_KEYS, DARK_ICON_KEYS } from '../../../main/ets/model/iconcatalog';
import { hasDarkIcon, iconKeyForIssuer, isDefaultIconKey } from '../../../main/ets/model/iconresolver';
import { convertExternalBackup } from '../../../main/ets/model/imports';
import { xchacha20poly1305 } from '../../../main/ets/model/noble-ciphers/chacha.js';
import util from '@ohos.util';
import * as kdbxweb from 'kdbxweb';
import { ohosArgon2 } from 'kdbxweb/src/main/ets/crypto/argon2-rs';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { argon2id } from '@noble/hashes/argon2.js';

function testAuthenticator(type: AuthenticatorType, secret: string): AuthenticatorRecord {
  const record = createAuthenticator(type);
  record.issuer = 'Test';
  record.secret = secret;
  return record;
}

async function encryptAesGcmForTest(keyBytes: Uint8Array, iv: Uint8Array, plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)): Promise<Uint8Array> {
  const key = await cryptoFramework.createSymKeyGenerator('AES256').convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|GCM|NoPadding');
  const params: cryptoFramework.GcmParamsSpec = {
    algName: 'GcmParamsSpec',
    iv: { data: iv },
    aad: { data: aad },
    authTag: { data: new Uint8Array(0) }
  };
  await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, key, params);
  return (await cipher.doFinal({ data: plaintext })).data;
}

async function encryptAesCbcForTest(keyBytes: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await cryptoFramework.createSymKeyGenerator('AES256').convertKey({ data: keyBytes });
  const cipher = cryptoFramework.createCipher('AES256|CBC|PKCS7');
  const params: cryptoFramework.IvParamsSpec = { algName: 'IvParamsSpec', iv: { data: iv } };
  await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, key, params);
  return (await cipher.doFinal({ data: plaintext })).data;
}

function base64ForTest(data: Uint8Array): string {
  return new util.Base64Helper().encodeToStringSync(data);
}

function hexForTest(data: Uint8Array): string {
  let text = '';
  for (const byte of data) {
    text += byte.toString(16).padStart(2, '0');
  }
  return text;
}

function concatForTest(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

function derGcmParametersForTest(iv: Uint8Array): Uint8Array {
  const result = new Uint8Array(2 + 2 + iv.length + 3);
  result[0] = 0x30;
  result[1] = 2 + iv.length + 3;
  result[2] = 0x04;
  result[3] = iv.length;
  result.set(iv, 4);
  result[4 + iv.length] = 0x02;
  result[5 + iv.length] = 1;
  result[6 + iv.length] = 128;
  return result;
}

function freeOtpStringMapForTest(pairs: Array<FreeOtpMapPair>): Uint8Array {
  const bytes: Array<number> = [0xac, 0xed, 0x00, 0x05, 0x77, 0x04, 0x00, 0x00, 0x00, pairs.length];
  for (const pair of pairs) {
    for (const value of [pair.key, pair.value]) {
      const encoded = utf8Bytes(value);
      bytes.push(0x74, (encoded.length >>> 8) & 0xff, encoded.length & 0xff);
      for (const byte of encoded) {
        bytes.push(byte);
      }
    }
  }
  return new Uint8Array(bytes);
}

interface AndOtpTestToken {
  type: string;
  secret: string;
  issuer: string;
  label: string;
  algorithm: string;
  digits: number;
}

interface FreeOtpPlusTestToken {
  type: string;
  secret: string;
  issuerExt: string;
  label: string;
  algo: string;
}

interface FreeOtpPlusTestBackup {
  tokens: Array<FreeOtpPlusTestToken>;
}

interface ProtonTestContent {
  uri: string;
  name: string;
  entry_type: string;
}

interface ProtonTestEntry {
  content: ProtonTestContent;
}

interface ProtonTestBackup {
  version: number;
  entries: Array<ProtonTestEntry>;
}

interface LastPassTestFolder {
  id: string;
  name: string;
}

interface LastPassTestFolderData {
  folderId: string;
  position: number;
}

interface LastPassTestAccount {
  issuerName: string;
  userName: string;
  secret: string;
  timeStep: number;
  digits: number;
  algorithm: string;
  folderData: LastPassTestFolderData;
}

interface LastPassTestBackup {
  version: number;
  folders: Array<LastPassTestFolder>;
  accounts: Array<LastPassTestAccount>;
}

interface LargeBackupAuthenticator {
  Type: number;
  Issuer: string;
  Secret: string;
  Algorithm: number;
  Digits: number;
  Period: number;
  Counter: number;
  Ranking: number;
  CopyCount: number;
}

interface LargeBackupDocument {
  Authenticators: Array<LargeBackupAuthenticator>;
}

interface AegisGcmParams {
  nonce: string;
  tag: string;
}

interface AegisPasswordSlot {
  type: number;
  key: string;
  key_params: AegisGcmParams;
  salt: string;
  n: number;
  r: number;
  p: number;
}

interface AegisHeader {
  params: AegisGcmParams;
  slots: Array<AegisPasswordSlot>;
}

interface AegisInfo {
  secret: string;
  algo: string;
  digits: number;
  period: number;
  counter: number;
  pin: string;
}

interface AegisEntry {
  type: string;
  name: string;
  issuer: string;
  group: string;
  icon: string;
  info: AegisInfo;
}

interface AegisDatabase {
  entries: Array<AegisEntry>;
}

interface AegisBackup {
  version: number;
  header: AegisHeader;
  db: string;
}

interface TwoFasOtp {
  account: string;
  issuer: string;
  digits: number;
  period: number;
  algorithm: string;
  counter: number;
  tokenType: string;
}

interface TwoFasService {
  name: string;
  secret: string;
  otp: TwoFasOtp;
  groupId: string;
}

interface TwoFasGroup {
  id: string;
  name: string;
}

interface TwoFasBackup {
  servicesEncrypted: string;
  groups: Array<TwoFasGroup>;
}

interface BitwardenFolder {
  id: string;
  name: string;
}

interface BitwardenLogin {
  username: string;
  totp: string;
}

interface BitwardenItem {
  id: string;
  type: number;
  name: string;
  folderId: string;
  login: BitwardenLogin;
}

interface BitwardenVault {
  folders: Array<BitwardenFolder>;
  items: Array<BitwardenItem>;
}

interface BitwardenEncryptedExport {
  encrypted: boolean;
  passwordProtected: boolean;
  kdfType: number;
  kdfIterations: number;
  salt: string;
  data: string;
}

interface EnteKdfParams {
  memLimit: number;
  opsLimit: number;
  salt: string;
}

interface EnteBackupFixture {
  version: number;
  kdfParams: EnteKdfParams;
  encryptionNonce: string;
  encryptedData: string;
}

interface FreeOtpEncryptedValue {
  mCipher: string;
  mParameters: string;
  mToken: string;
  mCipherText: string;
}

interface FreeOtpMasterFixture {
  mAlgorithm: string;
  mIterations: number;
  mSalt: string;
  mEncryptedKey: string;
}

interface FreeOtpTokenFixture {
  mToken: string;
  mType: string;
  mIssuer: string;
  mLabel: string;
  mAlgorithm: string;
  mDigits: number;
}

interface FreeOtpPairedFixture {
  key: string;
}

interface FreeOtpMapPair {
  key: string;
  value: string;
}

interface TotpAuthenticatorFixture {
  issuer: string;
  name: string;
  key: string;
  digits: string;
  period: string;
  base: number;
}

export default function abilityTest() {
  describe('Harmony Authenticator emulator tests', () => {
    it('matches TOTP SHA-1, SHA-256, and SHA-512 vectors', 0, () => {
      const sha1 = testAuthenticator('TOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      sha1.digits = 8;
      expect(computeOtp(sha1, 59)).assertEqual('94287082');

      const sha256 = testAuthenticator('TOTP',
        'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA');
      sha256.algorithm = 'SHA256';
      sha256.digits = 8;
      expect(computeOtp(sha256, 59)).assertEqual('46119246');

      const sha512 = testAuthenticator('TOTP',
        'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA');
      sha512.algorithm = 'SHA512';
      sha512.digits = 8;
      expect(computeOtp(sha512, 59)).assertEqual('90693936');
    });

    it('matches HOTP, mOTP, Steam, and Yandex vectors', 0, () => {
      const hotp = testAuthenticator('HOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      expect(computeOtp(hotp, 0)).assertEqual('755224');

      const motp = testAuthenticator('mOTP', '7ac61d4736f51a2b');
      motp.pin = '5555';
      expect(computeMotp(motp.secret, motp.pin, 1000000000)).assertEqual('4af383');
      expect(computeOtp(motp, 1000000000)).assertEqual('2783ae');

      const steam = testAuthenticator('Steam', '63BEDWCQZKTQWPESARIERL5DTTQFCJTK');
      expect(computeOtp(steam, 1511200518)).assertEqual('FR8RV');

      const yandex = testAuthenticator('Yandex', 'LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI');
      yandex.pin = '7586';
      expect(computeOtp(yandex, 1581064020)).assertEqual('oactmacq');
    });

    it('parses standard and Google migration OTP URIs', 0, () => {
      const parsed = parseOtpUri(
        'otpauth://totp/Example%3Aalice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60'
      );
      expect(parsed.authenticator.username).assertEqual('alice');
      expect(parsed.authenticator.algorithm).assertEqual('SHA256');
      expect(parsed.authenticator.period).assertEqual(60);

      const migrated = parseGoogleMigrationUri(
        'otpauth-migration://offline?data=CjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5FeGFtcGxlOiBBbGljZRoHRXhhbXBsZSACKAIwAg=='
      );
      expect(migrated.length).assertEqual(1);
      expect(migrated[0].issuer).assertEqual('Example');
      expect(migrated[0].username).assertEqual('Alice');
      expect(migrated[0].algorithm).assertEqual('SHA256');
    });

    it('creates QR-compatible URIs for standard OTP types', 0, () => {
      const totp = testAuthenticator('TOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      totp.username = 'alice@example.com';
      totp.period = 60;
      const totpUri = authenticatorUri(totp);
      expect(totpUri.startsWith('otpauth://totp/')).assertTrue();
      const parsedTotp = parseOtpUri(totpUri).authenticator;
      expect(parsedTotp.issuer).assertEqual(totp.issuer);
      expect(parsedTotp.username).assertEqual(totp.username);
      expect(parsedTotp.period).assertEqual(60);

      const hotp = testAuthenticator('HOTP', 'JBSWY3DPEHPK3PXP');
      hotp.counter = 7;
      const parsedHotp = parseOtpUri(authenticatorUri(hotp)).authenticator;
      expect(parsedHotp.type).assertEqual('HOTP');
      expect(parsedHotp.counter).assertEqual(7);
    });

    it('resolves the Android default icon catalog', 0, () => {
      expect(DEFAULT_ICON_KEYS.length).assertEqual(793);
      expect(DARK_ICON_KEYS.length).assertEqual(237);
      expect(iconKeyForIssuer('Google: Alice')).assertEqual('google');
      expect(iconKeyForIssuer('1Password')).assertEqual('1password');
      expect(isDefaultIconKey('github')).assertTrue();
      expect(hasDarkIcon('1password')).assertTrue();
    });

    it('matches native Argon2id output to the existing backup derivation', 0, async () => {
      const password = utf8Bytes('argon2-compatibility-test');
      const salt = new Uint8Array(16);
      salt.fill(0x5a);
      const expected = argon2id(password, salt, { t: 1, m: 32, p: 1, dkLen: 32 }) as Uint8Array;
      const passwordBuffer = new ArrayBuffer(password.length);
      const saltBuffer = new ArrayBuffer(salt.length);
      new Uint8Array(passwordBuffer).set(password);
      new Uint8Array(saltBuffer).set(salt);
      const actual = new Uint8Array(await ohosArgon2(passwordBuffer, saltBuffer, 32, 1, 32, 1, 2, 0x13));
      expect(hexForTest(actual)).assertEqual(hexForTest(expected));
      password.fill(0);
      salt.fill(0);
      actual.fill(0);
      expected.fill(0);
    });

    it('imports WinAuth ZIPs containing OTP URI lists', 0, async () => {
      const archive = new util.Base64Helper().decodeSync(
        'UEsDBBQAAAAAAIi7eF39FDPwKwAAACsAAAAKAAAAYmFja3VwLnR4dG90cGF1dGg6Ly90b3RwL1Rlc3Q/c2VjcmV0PUpCU1dZM0RQRUhQSzNQWFBQSwECFAAUAAAAAACIu3hd/RQz8CsAAAArAAAACgAAAAAAAAAAAAAAgAEAAAAAYmFja3VwLnR4dFBLBQYAAAAAAQABADgAAABTAAAAAAA='
      );
      const imported = await convertExternalBackup('winauth', archive);
      expect(imported.vault.authenticators.length).assertEqual(1);
      expect(imported.vault.authenticators[0].issuer).assertEqual('Test');
      expect(imported.vault.authenticators[0].secret).assertEqual('JBSWY3DPEHPK3PXP');

      const deflatedArchive = new util.Base64Helper().decodeSync(
        'UEsDBBQAAAAIAGoKeV39FDPwLQAAACsAAAAKAAAAYmFja3VwLnR4dMsvKUgsLcmw0tcvyS8p0A9JLS6xL05NLkotsfVyCg6PNHYJcPUI8DYOiAgAAFBLAQIUABQAAAAIAGoKeV39FDPwLQAAACsAAAAKAAAAAAAAAAAAAACAAQAAAABiYWNrdXAudHh0UEsFBgAAAAABAAEAOAAAAFUAAAAAAA=='
      );
      const deflatedImport = await convertExternalBackup('winauth', deflatedArchive);
      expect(deflatedImport.vault.authenticators.length).assertEqual(1);
    });

    it('imports plaintext andOTP, FreeOTP+, Proton, and LastPass backups', 0, async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const andOtpToken: AndOtpTestToken = {
        type: 'TOTP',
        secret,
        issuer: 'andOTP',
        label: 'alice',
        algorithm: 'SHA1',
        digits: 6
      };
      const andOtp = await convertExternalBackup('andotp', utf8Bytes(JSON.stringify([andOtpToken])));
      expect(andOtp.vault.authenticators[0].issuer).assertEqual('andOTP');

      const freeOtpPlusToken: FreeOtpPlusTestToken = {
        type: 'TOTP',
        secret,
        issuerExt: 'FreeOTP',
        label: 'bob',
        algo: 'SHA1'
      };
      const freeOtpPlusBackup: FreeOtpPlusTestBackup = { tokens: [freeOtpPlusToken] };
      const freeOtpPlus = await convertExternalBackup('freeotp-plus', utf8Bytes(JSON.stringify(freeOtpPlusBackup)));
      expect(freeOtpPlus.vault.authenticators[0].username).assertEqual('bob');

      const uri = 'otpauth://totp/Proton%3Acarol?secret=JBSWY3DPEHPK3PXP&issuer=Proton';
      const protonContent: ProtonTestContent = { uri, name: 'carol', entry_type: 'Totp' };
      const protonEntry: ProtonTestEntry = {
        content: protonContent
      };
      const protonBackup: ProtonTestBackup = {
        version: 1,
        entries: [protonEntry]
      };
      const proton = await convertExternalBackup('proton', utf8Bytes(JSON.stringify(protonBackup)));
      expect(proton.vault.authenticators[0].issuer).assertEqual('Proton');

      const folderData: LastPassTestFolderData = { folderId: 'work', position: 0 };
      const lastPassAccount: LastPassTestAccount = {
        issuerName: 'LastPass',
        userName: 'dave',
        secret,
        timeStep: 30,
        digits: 6,
        algorithm: 'SHA1',
        folderData
      };
      const lastPassFolder: LastPassTestFolder = { id: 'work', name: 'Work' };
      const lastPassBackup: LastPassTestBackup = {
        version: 3,
        folders: [lastPassFolder],
        accounts: [lastPassAccount]
      };
      const lastPass = await convertExternalBackup('lastpass', utf8Bytes(JSON.stringify(lastPassBackup)));
      expect(lastPass.vault.authenticators[0].categoryId.length > 0).assertTrue();
    });

    it('imports encrypted FreeOTP and TOTP Authenticator backups', 0, async () => {
      const password = 'freeotp-test-password';
      const salt = new Uint8Array(16);
      salt.fill(0x12);
      const iterations = 10;
      const kdf = cryptoFramework.createKdf('PBKDF2|SHA1');
      const spec: cryptoFramework.PBKDF2Spec = {
        algName: 'PBKDF2',
        password,
        salt,
        iterations,
        keySize: 32
      };
      const wrappingKey = (await kdf.generateSecret(spec)).data;
      const masterKey = new Uint8Array(32);
      masterKey.fill(0x42);
      const masterIv = new Uint8Array(12);
      masterIv.fill(0x21);
      const tokenIv = new Uint8Array(12);
      tokenIv.fill(0x31);
      const masterAd = utf8Bytes('masterKey');
      const tokenAd = utf8Bytes('token-1');
      const encryptedMaster = await encryptAesGcmForTest(wrappingKey, masterIv, masterKey, masterAd);
      const encryptedSecret = await encryptAesGcmForTest(masterKey, tokenIv,
        utf8Bytes('JBSWY3DPEHPK3PXP'), tokenAd);
      const masterPayload: FreeOtpEncryptedValue = {
        mCipher: 'AES/GCM/NoPadding',
        mParameters: base64ForTest(derGcmParametersForTest(masterIv)),
        mToken: 'masterKey',
        mCipherText: base64ForTest(encryptedMaster)
      };
      const tokenPayload: FreeOtpEncryptedValue = {
        mCipher: 'AES/GCM/NoPadding',
        mParameters: base64ForTest(derGcmParametersForTest(tokenIv)),
        mToken: 'token-1',
        mCipherText: base64ForTest(encryptedSecret)
      };
      const master: FreeOtpMasterFixture = {
        mAlgorithm: 'PBKDF2withHmacSHA1',
        mIterations: iterations,
        mSalt: base64ForTest(salt),
        mEncryptedKey: JSON.stringify(masterPayload)
      };
      const token: FreeOtpTokenFixture = {
        mToken: 'token-1',
        mType: 'TOTP',
        mIssuer: 'FreeOTP',
        mLabel: 'alice',
        mAlgorithm: 'SHA1',
        mDigits: 6
      };
      const paired: FreeOtpPairedFixture = { key: JSON.stringify(tokenPayload) };
      const serialized = freeOtpStringMapForTest([
        { key: 'masterKey', value: JSON.stringify(master) },
        { key: 'token-1-token', value: JSON.stringify(token) },
        { key: 'token-1', value: JSON.stringify(paired) }
      ]);
      const freeOtp = await convertExternalBackup('freeotp', serialized, password);
      expect(freeOtp.vault.authenticators.length).assertEqual(1);
      expect(freeOtp.vault.authenticators[0].issuer).assertEqual('FreeOTP');
      expect(freeOtp.vault.authenticators[0].secret).assertEqual('JBSWY3DPEHPK3PXP');
      wrappingKey.fill(0);
      masterKey.fill(0);

      const totpPassword = 'totp-authenticator-password';
      const totpKey = sha256(utf8Bytes(totpPassword)) as Uint8Array;
      const totpAccount: TotpAuthenticatorFixture = {
        issuer: 'TOTP Authenticator',
        name: 'bob',
        key: '48656c6c6f21',
        digits: '6',
        period: '30',
        base: 16
      };
      const malformedWrapper = `xx${JSON.stringify([totpAccount])}ignored`;
      const encryptedTotp = await encryptAesCbcForTest(totpKey, new Uint8Array(16), utf8Bytes(malformedWrapper));
      const totp = await convertExternalBackup('totp-authenticator', utf8Bytes(base64ForTest(encryptedTotp)),
        totpPassword);
      expect(totp.vault.authenticators.length).assertEqual(1);
      expect(totp.vault.authenticators[0].issuer).assertEqual('TOTP Authenticator');
      totpKey.fill(0);
    });

    it('decrypts encrypted andOTP backups with their documented envelope', 0, async () => {
      const password = 'andotp-test-password';
      const iterations = 10;
      const salt = new Uint8Array(12);
      const iv = new Uint8Array(12);
      for (let index = 0; index < salt.length; index++) {
        salt[index] = index + 1;
        iv[index] = index + 13;
      }
      const kdf = cryptoFramework.createKdf('PBKDF2|SHA1');
      const spec: cryptoFramework.PBKDF2Spec = {
        algName: 'PBKDF2',
        password,
        salt,
        iterations,
        keySize: 32
      };
      const keyBytes = (await kdf.generateSecret(spec)).data;
      const key = await cryptoFramework.createSymKeyGenerator('AES256').convertKey({ data: keyBytes });
      const cipher = cryptoFramework.createCipher('AES256|GCM|NoPadding');
      const params: cryptoFramework.GcmParamsSpec = {
        algName: 'GcmParamsSpec',
        iv: { data: iv },
        aad: { data: new Uint8Array(0) },
        authTag: { data: new Uint8Array(0) }
      };
      await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, key, params);
      const encryptedToken: AndOtpTestToken = {
        type: 'TOTP',
        issuer: 'Encrypted andOTP',
        label: 'alice',
        secret: 'JBSWY3DPEHPK3PXP',
        digits: 6,
        algorithm: 'SHA1'
      };
      const plaintext = utf8Bytes(JSON.stringify([encryptedToken]));
      const encrypted = (await cipher.doFinal({ data: plaintext })).data;
      const backup = new Uint8Array(4 + salt.length + iv.length + encrypted.length);
      backup[0] = 0;
      backup[1] = 0;
      backup[2] = 0;
      backup[3] = iterations;
      backup.set(salt, 4);
      backup.set(iv, 16);
      backup.set(encrypted, 28);
      const imported = await convertExternalBackup('andotp', backup, password);
      expect(imported.vault.authenticators[0].issuer).assertEqual('Encrypted andOTP');
      keyBytes.fill(0);
    });

    it('decrypts encrypted Aegis and 2FAS backups', 0, async () => {
      const aegisPassword = 'aegis-test-password';
      const salt = new Uint8Array(16);
      const slotNonce = new Uint8Array(12);
      const databaseNonce = new Uint8Array(12);
      for (let index = 0; index < salt.length; index++) {
        salt[index] = index + 1;
      }
      for (let index = 0; index < 12; index++) {
        slotNonce[index] = index + 20;
        databaseNonce[index] = index + 40;
      }
      const scrypt = cryptoFramework.createKdf('SCRYPT');
      const scryptSpec: cryptoFramework.ScryptSpec = {
        algName: 'SCRYPT',
        passphrase: aegisPassword,
        salt,
        n: 1024,
        r: 1,
        p: 1,
        maxMemory: 32 * 1024 * 1024,
        keySize: 32
      };
      const wrappingKey = (await scrypt.generateSecret(scryptSpec)).data;
      const masterKey = new Uint8Array(32);
      masterKey.fill(0x37);
      const encryptedMaster = await encryptAesGcmForTest(wrappingKey, slotNonce, masterKey);
      const aegisEntry: AegisEntry = {
        type: 'totp',
        name: 'alice',
        issuer: 'Aegis',
        group: 'Work',
        icon: '',
        info: {
          secret: 'JBSWY3DPEHPK3PXP',
          algo: 'SHA1',
          digits: 6,
          period: 30,
          counter: 0,
          pin: ''
        }
      };
      const database: AegisDatabase = { entries: [aegisEntry] };
      const encryptedDatabase = await encryptAesGcmForTest(masterKey, databaseNonce,
        utf8Bytes(JSON.stringify(database)));
      const slotParams: AegisGcmParams = {
        nonce: hexForTest(slotNonce),
        tag: hexForTest(encryptedMaster.subarray(encryptedMaster.length - 16))
      };
      const dbParams: AegisGcmParams = {
        nonce: hexForTest(databaseNonce),
        tag: hexForTest(encryptedDatabase.subarray(encryptedDatabase.length - 16))
      };
      const slot: AegisPasswordSlot = {
        type: 1,
        key: hexForTest(encryptedMaster.subarray(0, encryptedMaster.length - 16)),
        key_params: slotParams,
        salt: hexForTest(salt),
        n: 1024,
        r: 1,
        p: 1
      };
      const aegisBackup: AegisBackup = {
        version: 1,
        header: { params: dbParams, slots: [slot] },
        db: base64ForTest(encryptedDatabase.subarray(0, encryptedDatabase.length - 16))
      };
      const aegis = await convertExternalBackup('aegis', utf8Bytes(JSON.stringify(aegisBackup)), aegisPassword);
      expect(aegis.vault.authenticators[0].issuer).assertEqual('Aegis');
      expect(aegis.vault.categories[0].name).assertEqual('Work');
      wrappingKey.fill(0);
      masterKey.fill(0);

      const twoFasPassword = '2fas-test-password';
      const twoFasSalt = new Uint8Array(16);
      const twoFasIv = new Uint8Array(12);
      twoFasSalt.fill(0x51);
      twoFasIv.fill(0x26);
      const pbkdf = cryptoFramework.createKdf('PBKDF2|SHA256');
      const pbkdfSpec: cryptoFramework.PBKDF2Spec = {
        algName: 'PBKDF2',
        password: twoFasPassword,
        salt: twoFasSalt,
        iterations: 10_000,
        keySize: 32
      };
      const twoFasKey = (await pbkdf.generateSecret(pbkdfSpec)).data;
      const service: TwoFasService = {
        name: '2FAS account',
        secret: 'JBSWY3DPEHPK3PXP',
        otp: {
          account: 'bob',
          issuer: '2FAS',
          digits: 6,
          period: 30,
          algorithm: 'SHA1',
          counter: 0,
          tokenType: 'TOTP'
        },
        groupId: 'group-1'
      };
      const encryptedServices = await encryptAesGcmForTest(twoFasKey, twoFasIv,
        utf8Bytes(JSON.stringify([service])));
      const group: TwoFasGroup = { id: 'group-1', name: 'Personal' };
      const twoFasBackup: TwoFasBackup = {
        servicesEncrypted: `${base64ForTest(encryptedServices)}:${base64ForTest(twoFasSalt)}:${base64ForTest(twoFasIv)}`,
        groups: [group]
      };
      const twoFas = await convertExternalBackup('twofas', utf8Bytes(JSON.stringify(twoFasBackup)), twoFasPassword);
      expect(twoFas.vault.authenticators[0].issuer).assertEqual('2FAS');
      expect(twoFas.vault.categories[0].name).assertEqual('Personal');
      twoFasKey.fill(0);
    });

    it('decrypts password-protected Bitwarden exports', 0, async () => {
      const password = 'bitwarden-test-password';
      const saltText = 'synthetic-bitwarden-salt';
      const saltBytes = utf8Bytes(saltText);
      const kdf = cryptoFramework.createKdf('PBKDF2|SHA256');
      const spec: cryptoFramework.PBKDF2Spec = {
        algName: 'PBKDF2',
        password,
        salt: saltBytes,
        iterations: 10,
        keySize: 32
      };
      const masterKey = (await kdf.generateSecret(spec)).data;
      const encryptionKey = hkdf(sha256, masterKey, undefined, utf8Bytes('enc'), 32) as Uint8Array;
      const macKey = hkdf(sha256, masterKey, undefined, utf8Bytes('mac'), 32) as Uint8Array;
      const iv = new Uint8Array(16);
      iv.fill(0x24);
      const vault: BitwardenVault = {
        folders: [{ id: 'work', name: 'Work' }],
        items: [{
          id: 'item-1',
          type: 1,
          name: 'Bitwarden',
          folderId: 'work',
          login: { username: 'alice', totp: 'JBSWY3DPEHPK3PXP' }
        }]
      };
      const ciphertext = await encryptAesCbcForTest(encryptionKey, iv, utf8Bytes(JSON.stringify(vault)));
      const mac = hmac(sha256, macKey, concatForTest(iv, ciphertext)) as Uint8Array;
      const encryptedExport: BitwardenEncryptedExport = {
        encrypted: true,
        passwordProtected: true,
        kdfType: 0,
        kdfIterations: 10,
        salt: saltText,
        data: `2.${base64ForTest(iv)}|${base64ForTest(ciphertext)}|${base64ForTest(mac)}`
      };
      const imported = await convertExternalBackup('bitwarden', utf8Bytes(JSON.stringify(encryptedExport)), password);
      expect(imported.vault.authenticators.length).assertEqual(1);
      expect(imported.vault.authenticators[0].issuer).assertEqual('Bitwarden');
      expect(imported.vault.authenticators[0].username).assertEqual('alice');
      expect(imported.vault.categories[0].name).assertEqual('Work');
      masterKey.fill(0);
      encryptionKey.fill(0);
      macKey.fill(0);
      saltBytes.fill(0);
    });

    it('decrypts Ente Auth XChaCha20 backups', 0, async () => {
      const password = 'ente-test-password';
      const salt = new Uint8Array(16);
      const nonce = new Uint8Array(24);
      salt.fill(0x31);
      for (let index = 0; index < nonce.length; index++) {
        nonce[index] = index + 1;
      }
      const key = argon2id(utf8Bytes(password), salt, { t: 1, m: 8, p: 1, dkLen: 32 }) as Uint8Array;
      const plaintext = utf8Bytes('otpauth://totp/Ente%3Auser?secret=JBSWY3DPEHPK3PXP&issuer=Ente');
      const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext);
      const kdfParams: EnteKdfParams = {
        memLimit: 8192,
        opsLimit: 1,
        salt: base64ForTest(salt)
      };
      const backup: EnteBackupFixture = {
        version: 1,
        kdfParams,
        encryptionNonce: base64ForTest(nonce),
        encryptedData: base64ForTest(ciphertext)
      };
      const imported = await convertExternalBackup('ente', utf8Bytes(JSON.stringify(backup)), password);
      expect(imported.vault.authenticators.length).assertEqual(1);
      expect(imported.vault.authenticators[0].issuer).assertEqual('Ente');
      key.fill(0);
      salt.fill(0);
    });

    it('imports KeePass entries containing OTP URIs', 0, async () => {
      kdbxweb.CryptoEngine.setArgon2Impl(ohosArgon2);
      const password = 'keepass-import-test';
      const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password));
      const database = kdbxweb.Kdbx.create(credentials, 'Synthetic import');
      const group = database.createGroup(database.getDefaultGroup(), 'Work');
      const entry = database.createEntry(group);
      entry.setField('otp', 'otpauth://totp/KeePass%3Auser?secret=JBSWY3DPEHPK3PXP&issuer=KeePass');
      const bytes = new Uint8Array(await database.save());
      const imported = await convertExternalBackup('keepass', bytes, password);
      expect(imported.vault.authenticators.length).assertEqual(1);
      expect(imported.vault.authenticators[0].issuer).assertEqual('KeePass');
      expect(imported.vault.categories[0].name).assertEqual('Work');
    });

    it('merges backup entries without removing local accounts or categories', 0, () => {
      const existing = emptyVault();
      const existingCategory: AuthenticatorCategory = {
        id: 'local-work',
        name: 'Work',
        ranking: 0
      };
      existing.categories.push(existingCategory);
      const existingAuthenticator = testAuthenticator('TOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      existingAuthenticator.id = 'existing-local-id';
      existingAuthenticator.issuer = 'Existing';
      existingAuthenticator.categoryId = existingCategory.id;
      existing.authenticators.push(existingAuthenticator);
      const existingIcon: CustomIcon = { id: 'local-icon', data: 'local-icon-data' };
      existing.customIcons.push(existingIcon);

      const imported = emptyVault();
      const matchingCategory: AuthenticatorCategory = {
        id: 'backup-work',
        name: 'work',
        ranking: 0
      };
      const newCategory: AuthenticatorCategory = {
        id: 'backup-imported',
        name: 'Imported',
        ranking: 1
      };
      imported.categories.push(matchingCategory, newCategory);
      const updatedAuthenticator = testAuthenticator('TOTP', existingAuthenticator.secret);
      updatedAuthenticator.id = 'backup-id';
      updatedAuthenticator.issuer = 'Updated';
      updatedAuthenticator.categoryId = matchingCategory.id;
      imported.authenticators.push(updatedAuthenticator);
      const newAuthenticator = testAuthenticator('HOTP', 'JBSWY3DPEHPK3PXP');
      newAuthenticator.issuer = 'New';
      newAuthenticator.categoryId = newCategory.id;
      imported.authenticators.push(newAuthenticator);
      const duplicateIcon: CustomIcon = { id: 'local-icon', data: 'backup-icon-data' };
      const importedIcon: CustomIcon = { id: 'imported-icon', data: 'imported-icon-data' };
      imported.customIcons.push(duplicateIcon, importedIcon);

      const merged = mergeVaults(existing, imported);
      expect(merged.authenticators.length).assertEqual(2);
      expect(merged.authenticators[0].id).assertEqual('existing-local-id');
      expect(merged.authenticators[0].issuer).assertEqual('Updated');
      expect(merged.authenticators[0].categoryId).assertEqual('local-work');
      expect(merged.authenticators[1].categoryId).assertEqual('backup-imported');
      expect(merged.categories.length).assertEqual(2);
      expect(merged.customIcons.length).assertEqual(2);
      expect(merged.customIcons[0].data).assertEqual('local-icon-data');
    });

    it('imports unencrypted JSON without a password', 0, async () => {
      const cleartext = utf8Bytes('{"Authenticators":[]}');
      const restored = await decryptAuthPro(cleartext, '');
      expect(restored.authenticators.length).assertEqual(0);
    });

    it('parses large unencrypted backups without blocking the caller', 0, async () => {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      const authenticators: Array<LargeBackupAuthenticator> = [];
      for (let index = 0; index < 1000; index++) {
        let value = index;
        let suffix = '';
        for (let digit = 0; digit < 4; digit++) {
          suffix = alphabet.charAt(value % 32) + suffix;
          value = Math.floor(value / 32);
        }
        const account: LargeBackupAuthenticator = {
          Type: 2,
          Issuer: `Service ${index}`,
          Secret: `JBSWY3DPEHPK3PXP${suffix}`,
          Algorithm: 0,
          Digits: 6,
          Period: 30,
          Counter: 0,
          Ranking: index,
          CopyCount: 0
        };
        authenticators.push(account);
      }
      const backup: LargeBackupDocument = { Authenticators: authenticators };
      const restored = await decryptAuthPro(utf8Bytes(JSON.stringify(backup)), '');
      expect(restored.authenticators.length).assertEqual(1000);
    });

    it('parses Stratum icon-pack protobuf entries', 0, () => {
      const pack = parseStratumIconPack(new Uint8Array([
        0x0a, 0x04, 0x54, 0x65, 0x73, 0x74,
        0x22, 0x10,
        0x0a, 0x04, 0x6c, 0x6f, 0x67, 0x6f,
        0x12, 0x08, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
      ]));
      expect(pack.name).assertEqual('Test');
      expect(pack.icons.length).assertEqual(1);
      expect(pack.icons[0].name).assertEqual('logo');
      expect(pack.icons[0].data).assertEqual('iVBORw0KGgo=');
    });

    it('round-trips strong and legacy Authenticator Pro backups on-device', 0, async () => {
      const source = emptyVault();
      const record = testAuthenticator('TOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      record.issuer = 'Synthetic emulator test';
      source.authenticators.push(record);

      const strong = await encryptAuthPro(source, 'emulator-only-test-password');
      const strongRestored = await decryptAuthPro(strong, 'emulator-only-test-password');
      expect(strongRestored.authenticators.length).assertEqual(1);
      expect(strongRestored.authenticators[0].issuer).assertEqual(record.issuer);

      const legacy = await encryptLegacyAuthPro(source, 'emulator-only-test-password');
      const legacyRestored = await decryptAuthPro(legacy, 'emulator-only-test-password');
      expect(legacyRestored.authenticators.length).assertEqual(1);
      expect(legacyRestored.authenticators[0].secret).assertEqual(record.secret);
    });
  });
}
