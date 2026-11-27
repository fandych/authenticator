import { describe, it, expect } from '@ohos/hypium';
import { decryptAuthPro, decryptFunBackup, encryptAuthPro, encryptFunBackup, encryptLegacyAuthPro } from '../main/ets/model/backup';
import { AuthenticatorRecord, AuthenticatorType, computeMotp, computeOtp, createAuthenticator, emptyVault, parseOtpUri, utf8Bytes } from '../main/ets/model/otp';
import { parseGoogleMigrationUri } from '../main/ets/model/migration';
import util from '@ohos.util';

function testAuthenticator(type: AuthenticatorType, secret: string): AuthenticatorRecord {
  const record = createAuthenticator(type);
  record.issuer = 'Test';
  record.secret = secret;
  return record;
}

export default function localUnitTest() {
  describe('Authenticator core', () => {
    it('matches RFC TOTP vectors for SHA-1, SHA-256, and SHA-512', 0, () => {
      const sha1Record = testAuthenticator('TOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      sha1Record.digits = 8;
      expect(computeOtp(sha1Record, 59)).assertEqual('94287082');

      const sha256Record = testAuthenticator('TOTP',
        'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA');
      sha256Record.algorithm = 'SHA256';
      sha256Record.digits = 8;
      expect(computeOtp(sha256Record, 59)).assertEqual('46119246');

      const sha512Record = testAuthenticator('TOTP',
        'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA');
      sha512Record.algorithm = 'SHA512';
      sha512Record.digits = 8;
      expect(computeOtp(sha512Record, 59)).assertEqual('90693936');
    });

    it('matches the HOTP counter vector', 0, () => {
      const record = testAuthenticator('HOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      expect(computeOtp(record, 0)).assertEqual('755224');
    });

    it('matches mOTP, Steam, and Yandex vectors', 0, () => {
      const mobile = testAuthenticator('mOTP', '7ac61d4736f51a2b');
      mobile.pin = '5555';
      expect(computeMotp(mobile.secret, mobile.pin, 0)).assertEqual('c42a26');
      expect(computeMotp(mobile.secret, mobile.pin, 1000000000)).assertEqual('4af383');
      expect(computeOtp(mobile, 1000000000)).assertEqual('2783ae');

      const steam = testAuthenticator('Steam', '63BEDWCQZKTQWPESARIERL5DTTQFCJTK');
      expect(computeOtp(steam, 1511200518)).assertEqual('FR8RV');

      const yandex = testAuthenticator('Yandex', 'LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI');
      yandex.pin = '7586';
      expect(computeOtp(yandex, 1581064020)).assertEqual('oactmacq');
    });

    it('parses standard OTP URIs without losing parameters', 0, () => {
      const parsed = parseOtpUri(
        'otpauth://totp/Example%3Aalice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60'
      );
      expect(parsed.authenticator.type).assertEqual('TOTP');
      expect(parsed.authenticator.issuer).assertEqual('Example');
      expect(parsed.authenticator.username).assertEqual('alice');
      expect(parsed.authenticator.algorithm).assertEqual('SHA256');
      expect(parsed.authenticator.digits).assertEqual(8);
      expect(parsed.authenticator.period).assertEqual(60);
    });

    it('parses Google Authenticator migration QR payloads', 0, () => {
      const imported = parseGoogleMigrationUri(
        'otpauth-migration://offline?data=CjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5FeGFtcGxlOiBBbGljZRoHRXhhbXBsZSACKAIwAg=='
      );
      expect(imported.length).assertEqual(1);
      expect(imported[0].issuer).assertEqual('Example');
      expect(imported[0].username).assertEqual('Alice');
      expect(imported[0].type).assertEqual('TOTP');
      expect(imported[0].algorithm).assertEqual('SHA256');
      expect(imported[0].digits).assertEqual(8);
      expect(imported[0].secret).assertEqual('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    });

    it('round-trips strong and legacy Authenticator Pro backups', 0, async () => {
      const source = emptyVault();
      const record = testAuthenticator('TOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      record.issuer = 'Synthetic test account';
      source.authenticators.push(record);
      const strong = await encryptAuthPro(source, 'test-only-password');
      const restoredStrong = await decryptAuthPro(strong, 'test-only-password');
      expect(restoredStrong.authenticators.length).assertEqual(1);
      expect(restoredStrong.authenticators[0].secret).assertEqual(record.secret);

      const legacy = await encryptLegacyAuthPro(source, 'test-only-password');
      const restoredLegacy = await decryptAuthPro(legacy, 'test-only-password');
      expect(restoredLegacy.authenticators.length).assertEqual(1);
      expect(restoredLegacy.authenticators[0].issuer).assertEqual(record.issuer);
    });

    it('round-trips encrypted FUN backups with a distinct versioned header', 0, async () => {
      const source = emptyVault();
      const record = testAuthenticator('TOTP', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      record.issuer = 'FUN backup account';
      record.categoryId = 'favorites';
      source.authenticators.push(record);
      source.categories.push({ id: 'favorites', name: 'Favorites', ranking: 0 });
      source.customIcons.push({ id: 'custom-1', data: 'data' });
      const backup = await encryptFunBackup(source, 'test-only-password');
      expect(new util.TextDecoder('utf-8').decodeToString(backup.subarray(0, 16)))
        .assertEqual('FUNAUTHENTICATOR');

      const restored = await decryptFunBackup(backup, 'test-only-password');
      expect(restored.authenticators.length).assertEqual(1);
      expect(restored.authenticators[0].issuer).assertEqual(record.issuer);
      expect(restored.authenticators[0].secret).assertEqual(record.secret);
      expect(restored.authenticators[0].categoryId).assertEqual('favorites');
      expect(restored.categories[0].name).assertEqual('Favorites');
      expect(restored.customIcons[0].id).assertEqual('custom-1');
    });

    it('imports unencrypted JSON without asking for a password', 0, async () => {
      const restored = await decryptAuthPro(utf8Bytes('{"Authenticators":[]}'), '');
      expect(restored.authenticators.length).assertEqual(0);
    });

  });
}
