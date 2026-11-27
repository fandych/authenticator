import { common } from '@kit.AbilityKit';
import { pasteboard } from '@kit.BasicServicesKit';
import { fileIo, picker } from '@kit.CoreFileKit';
import { scanBarcode, scanCore } from '@kit.ScanKit';
import { AuthenticatorCategory, AuthenticatorPatch, AuthenticatorRecord, AuthenticatorType, authenticatorUri, categoryIdForName, computeOtp, copyAuthenticator, copyVault, createAuthenticator, emptyVault, mergeVaults, OtpAlgorithm, parseOtpUri, patchAuthenticator, utf8Bytes, validateAuthenticator, VaultData } from '../model/otp';
import { parseGoogleMigrationUri } from '../model/migration';
import { decryptAuthPro, decryptFunBackup, encryptFunBackup } from '../model/backup';
import { AppPreferences, AuthenticatorSortMode, AuthenticatorViewMode, VaultStore } from '../model/store';
import { IconPack, IconPackEntry, parseStratumIconPack } from '../model/iconpack';
import { DEFAULT_ICON_KEYS } from '../model/iconcatalog';
import { hasDarkIcon, iconKeyForIssuer, isDefaultIconKey } from '../model/iconresolver';
import { convertExternalBackup, EXTERNAL_IMPORT_OPTIONS, ExternalImportFormat, ImportPasswordRequiredError, labelForFormat } from '../model/imports';
import { sha1 } from '@noble/hashes/legacy.js';
import util from '@ohos.util';

const TYPES: Array<AuthenticatorType> = ['TOTP', 'HOTP', 'mOTP', 'Steam', 'Yandex'];
const ALGORITHMS: Array<OtpAlgorithm> = ['SHA1', 'SHA256', 'SHA512'];

interface SortOption {
  mode: AuthenticatorSortMode;
  label: string;
}

@Entry
@Component
struct Index {
  @State private vault: VaultData = emptyVault();
  @State private darkMode: boolean = false;
  @State private nowSeconds: number = Math.floor(Date.now() / 1000);
  @State private searchVisible: boolean = false;
  @State private searchText: string = '';
  @State private selectedCategoryId: string = '';
  @State private showSettings: boolean = false;
  @State private showCategoryMenu: boolean = false;
  @State private showMainMenu: boolean = false;
  @State private showAddMenu: boolean = false;
  @State private showSortMenu: boolean = false;
  @State private showImportMenu: boolean = false;
  @State private showGuide: boolean = false;
  @State private accountMenuId: string = '';
  @State private reorderId: string = '';
  @State private categoryAssignmentId: string = '';
  @State private showAdvancedOptions: boolean = false;
  @State private showTypeOptions: boolean = false;
  @State private settingsPage: string = 'main';
  @State private viewMode: AuthenticatorViewMode = 'default';
  @State private sortMode: AuthenticatorSortMode = 'az';
  @State private codeGroupSize: number = 3;
  @State private showUsernames: boolean = true;
  @State private tapToCopy: boolean = true;
  @State private lockOrdering: boolean = false;
  @State private showEditor: boolean = false;
  @State private showPasswordDialog: boolean = false;
  @State private showRestoreDialog: boolean = false;
  @State private showDeleteDialog: boolean = false;
  @State private showMigrationDialog: boolean = false;
  @State private showIconPicker: boolean = false;
  @State private showQrCodeDialog: boolean = false;
  @State private showQrCopyWarning: boolean = false;
  @State private showIconPackDeleteDialog: boolean = false;
  @State private isBackupBusy: boolean = false;
  @State private isIconPackBusy: boolean = false;
  @State private editor: AuthenticatorRecord = createAuthenticator();
  @State private editingId: string = '';
  @State private uriText: string = '';
  @State private categoryName: string = '';
  @State private assignmentCategoryName: string = '';
  @State private password: string = '';
  @State private backupAction: string = '';
  @State private pendingBackupUri: string = '';
  @State private pendingDeleteId: string = '';
  @State private pendingRestoreVault: VaultData = emptyVault();
  @State private pendingMigrationAccounts: Array<AuthenticatorRecord> = [];
  @State private iconPacks: Array<IconPack> = [];
  @State private iconPickerAuthenticatorId: string = '';
  @State private selectedIconPackName: string = '';
  @State private iconSearchText: string = '';
  @State private pendingIconPackDeleteName: string = '';
  @State private pendingExternalImportFormat: ExternalImportFormat = 'uri-list';
  @State private pendingExternalImportUri: string = '';
  @State private busyMessage: string = '';
  @State private qrUri: string = '';
  @State private statusMessage: string = '';
  @State private digitsText: string = '6';
  @State private periodText: string = '30';
  @State private counterText: string = '0';

  private store: VaultStore | null = null;
  private context: common.UIAbilityContext | null = null;
  private timerId: number = -1;
  private readonly base64Helper: util.Base64Helper = new util.Base64Helper();
  private readonly iconSourceCache: Map<string, string> = new Map<string, string>();

  aboutToAppear(): void {
    this.context = this.getUIContext().getHostContext() as common.UIAbilityContext;
    this.timerId = setInterval(() => {
      this.nowSeconds = Math.floor(Date.now() / 1000);
    }, 1000);
    this.initialize();
  }

  aboutToDisappear(): void {
    if (this.timerId >= 0) {
      clearInterval(this.timerId);
      this.timerId = -1;
    }
  }

  private async initialize(): Promise<void> {
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      this.store = await VaultStore.open(this.context);
      this.vault = await this.store.load();
      this.darkMode = await this.store.loadDarkMode();
      const preferences = await this.store.loadAppPreferences();
      this.viewMode = preferences.viewMode;
      this.sortMode = preferences.sortMode;
      this.codeGroupSize = preferences.codeGroupSize;
      this.showUsernames = preferences.showUsernames;
      this.tapToCopy = preferences.tapToCopy;
      this.lockOrdering = preferences.lockOrdering;
      this.iconPacks = await this.store.loadIconPacks();
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private pageColor(): string {
    return this.darkMode ? '#111418' : '#F1F3F5';
  }

  private surfaceColor(): string {
    return this.darkMode ? '#202327' : '#FFFFFF';
  }

  private primaryTextColor(): string {
    return this.darkMode ? '#E8EAED' : '#202124';
  }

  private secondaryTextColor(): string {
    return this.darkMode ? '#BDC1C6' : '#5F6368';
  }

  private primaryColor(): string {
    return this.darkMode ? '#7AB8FF' : '#0A59F7';
  }

  private accentSoftColor(): string {
    return this.darkMode ? '#173A63' : '#DCEBFA';
  }

  private onAccentSoftColor(): string {
    return this.darkMode ? '#E1F0FF' : '#003B71';
  }

  private async saveVault(vault: VaultData = this.vault): Promise<void> {
    if (this.store === null) {
      throw new Error('The local data store is not ready yet.');
    }
    this.vault = await this.store.save(vault);
    this.iconSourceCache.clear();
  }

  private showSuccessToast(message: string): void {
    this.statusMessage = '';
    this.getUIContext().getPromptAction().showToast({ message, duration: 2000 });
  }

  private customIconSource(iconValue: string): string {
    if (!iconValue.startsWith('@')) {
      return '';
    }
    const id = iconValue.substring(1);
    const cached = this.iconSourceCache.get(id);
    if (cached !== undefined) {
      return cached;
    }
    const icon = this.vault.customIcons.find((item) => item.id === id);
    if (icon === undefined || icon.data.length === 0) {
      return '';
    }
    const source = this.iconImageSource(icon.data);
    this.iconSourceCache.set(id, source);
    return source;
  }

  private defaultIconSource(iconKey: string) {
    const key = isDefaultIconKey(iconKey) ? iconKey : 'default';
    const fileName = this.darkMode && hasDarkIcon(key) ? `${key}_dark` : key;
    return $rawfile(`icons/${fileName}.png`);
  }

  private defaultIconKey(item: AuthenticatorRecord): string {
    if (item.icon.length > 0 && !item.icon.startsWith('@') && isDefaultIconKey(item.icon)) {
      return item.icon;
    }
    return iconKeyForIssuer(item.issuer);
  }

  private filteredDefaultIconKeys(): Array<string> {
    const query = this.iconSearchText.trim().toLocaleLowerCase();
    return DEFAULT_ICON_KEYS.filter((key) => query.length === 0 || key.includes(query));
  }

  private customIconId(data: string): string {
    const digest = sha1(utf8Bytes(data)) as Uint8Array;
    let id = '';
    for (let index = 0; index < 4; index++) {
      const byte = digest[index];
      if (byte !== undefined) {
        id += byte.toString(16).padStart(2, '0');
      }
    }
    return id;
  }

  private visibleAuthenticators(): Array<AuthenticatorRecord> {
    const query = this.searchText.trim().toLocaleLowerCase();
    const filtered = this.vault.authenticators
      .filter((item) => this.selectedCategoryId.length === 0 ||
        (this.selectedCategoryId === '__uncategorized__' ? item.categoryId.length === 0 :
          item.categoryId === this.selectedCategoryId))
      .filter((item) => query.length === 0 ||
        item.issuer.toLocaleLowerCase().includes(query) ||
        item.username.toLocaleLowerCase().includes(query));
    switch (this.sortMode) {
      case 'za':
        return filtered.sort((left, right) => right.issuer.localeCompare(left.issuer));
      case 'mostCopied':
        return filtered.sort((left, right) => right.copyCount - left.copyCount ||
          left.issuer.localeCompare(right.issuer));
      case 'leastCopied':
        return filtered.sort((left, right) => left.copyCount - right.copyCount ||
          left.issuer.localeCompare(right.issuer));
      case 'custom':
        return filtered.sort((left, right) => left.ranking - right.ranking);
      default:
        return filtered.sort((left, right) => left.issuer.localeCompare(right.issuer));
    }
  }

  private async saveAppPreferences(viewMode: AuthenticatorViewMode = this.viewMode,
    sortMode: AuthenticatorSortMode = this.sortMode, codeGroupSize: number = this.codeGroupSize,
    showUsernames: boolean = this.showUsernames, tapToCopy: boolean = this.tapToCopy,
    lockOrdering: boolean = this.lockOrdering): Promise<void> {
    try {
      if (this.store === null) {
        throw new Error('The local data store is not ready yet.');
      }
      const preferences: AppPreferences = { viewMode, sortMode, codeGroupSize, showUsernames, tapToCopy, lockOrdering };
      await this.store.saveAppPreferences(preferences);
      this.viewMode = viewMode;
      this.sortMode = sortMode;
      this.codeGroupSize = codeGroupSize;
      this.showUsernames = showUsernames;
      this.tapToCopy = tapToCopy;
      this.lockOrdering = lockOrdering;
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private titleForCategory(): string {
    if (this.selectedCategoryId.length === 0) {
      return '全部';
    }
    if (this.selectedCategoryId === '__uncategorized__') {
      return '未分类';
    }
    const category = this.vault.categories.find((item) => item.id === this.selectedCategoryId);
    return category === undefined ? '全部' : category.name;
  }

  private openNewEditor(type: AuthenticatorType = 'TOTP'): void {
    this.editingId = '';
    this.editor = createAuthenticator(type);
    this.digitsText = String(this.editor.digits);
    this.periodText = String(this.editor.period);
    this.counterText = String(this.editor.counter);
    this.uriText = '';
    this.showAdvancedOptions = false;
    this.showTypeOptions = false;
    this.showEditor = true;
    this.statusMessage = '';
  }

  private openUriEditor(): void {
    this.openNewEditor();
    this.showAdvancedOptions = true;
  }

  private openGuide(): void {
    this.showAddMenu = false;
    this.showGuide = true;
  }

  private openEditEditor(item: AuthenticatorRecord): void {
    this.editingId = item.id;
    this.editor = copyAuthenticator(item);
    this.digitsText = String(item.digits);
    this.periodText = String(item.period);
    this.counterText = String(item.counter);
    this.uriText = '';
    this.showAdvancedOptions = false;
    this.showTypeOptions = false;
    this.showEditor = true;
    this.statusMessage = '';
  }

  private setEditor(patch: AuthenticatorPatch): void {
    this.editor = patchAuthenticator(this.editor, patch);
  }

  private async saveAuthenticator(): Promise<void> {
    try {
      const candidate = copyAuthenticator(this.editor);
      candidate.digits = Number(this.digitsText);
      candidate.period = Number(this.periodText);
      candidate.counter = Number(this.counterText);
      candidate.ranking = this.editingId.length === 0 ? this.vault.authenticators.length : this.editor.ranking;
      const validated = validateAuthenticator(candidate);
      const records: Array<AuthenticatorRecord> = [];
      let replaced = false;
      for (const item of this.vault.authenticators) {
        if (this.editingId.length > 0 && item.id === this.editingId) {
          records.push(validated);
          replaced = true;
        } else {
          records.push(copyAuthenticator(item));
        }
      }
      if (!replaced) {
        records.push(validated);
      }
      await this.saveVault(copyVault(this.vault, records));
      this.showEditor = false;
      this.showSuccessToast(this.editingId.length === 0 ? '账号已添加。' : '账号已保存。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async copyCode(item: AuthenticatorRecord): Promise<void> {
    try {
      const code = computeOtp(item, this.nowSeconds);
      const data = pasteboard.createData('text/plain', code);
      await pasteboard.getSystemPasteboard().setData(data);
      const updated: Array<AuthenticatorRecord> = [];
      for (const current of this.vault.authenticators) {
        const copy = copyAuthenticator(current);
        if (current.id === item.id) {
          copy.copyCount++;
          if (item.type === 'HOTP') {
            copy.counter++;
          }
        }
        updated.push(copy);
      }
      await this.saveVault(copyVault(this.vault, updated));
      this.showSuccessToast('验证码已复制。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async moveAuthenticator(item: AuthenticatorRecord, direction: number): Promise<void> {
    if (this.lockOrdering) {
      this.accountMenuId = '';
      this.statusMessage = '排序已锁定。';
      return;
    }
    if (this.sortMode !== 'custom') {
      await this.saveAppPreferences(this.viewMode, 'custom');
      if (!this.isCustomSortMode()) {
        return;
      }
    }
    const ordered = this.vault.authenticators.slice().sort((left, right) => left.ranking - right.ranking);
    const index = ordered.findIndex((current) => current.id === item.id);
    const destination = index + direction;
    if (index < 0 || destination < 0 || destination >= ordered.length) {
      return;
    }
    const current = ordered[index];
    ordered[index] = ordered[destination];
    ordered[destination] = current;
    const ranked: Array<AuthenticatorRecord> = [];
    for (let rank = 0; rank < ordered.length; rank++) {
      const entry = copyAuthenticator(ordered[rank]);
      entry.ranking = rank;
      ranked.push(entry);
    }
    try {
      await this.saveVault(copyVault(this.vault, ranked));
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async createCategory(): Promise<void> {
    const name = this.categoryName.trim();
    if (name.length === 0) {
      this.statusMessage = '请输入分类名称。';
      return;
    }
    const category: AuthenticatorCategory = {
      id: categoryIdForName(name),
      name,
      ranking: this.vault.categories.length
    };
    try {
      const categories = this.vault.categories.slice();
      categories.push(category);
      await this.saveVault(copyVault(this.vault, this.vault.authenticators, categories));
      this.categoryName = '';
      this.showSuccessToast('分类已添加。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async removeCategory(categoryId: string): Promise<void> {
    const categories = this.vault.categories.filter((item) => item.id !== categoryId);
    const authenticators: Array<AuthenticatorRecord> = [];
    for (const item of this.vault.authenticators) {
      const copy = copyAuthenticator(item);
      if (copy.categoryId === categoryId) {
        copy.categoryId = '';
      }
      authenticators.push(copy);
    }
    try {
      await this.saveVault(copyVault(this.vault, authenticators, categories));
      if (this.selectedCategoryId === categoryId) {
        this.selectedCategoryId = '';
      }
      this.showSuccessToast('分类已删除，账号已移至未分类。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async toggleTheme(): Promise<void> {
    const next = !this.darkMode;
    try {
      if (this.store === null) {
        throw new Error('The local data store is not ready yet.');
      }
      await this.store.saveDarkMode(next);
      this.darkMode = next;
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async scanOtpUri(): Promise<void> {
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      const result = await scanBarcode.startScanForResult(this.context, {
        scanTypes: [scanCore.ScanType.QR_CODE],
        enableAlbum: true
      });
      this.applyOtpUri(result.originalValue);
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private parseOtpUriField(): void {
    this.applyOtpUri(this.uriText);
  }

  private applyOtpUri(uri: string): void {
    try {
      if (uri.toLowerCase().startsWith('otpauth-migration://')) {
        this.pendingMigrationAccounts = parseGoogleMigrationUri(uri);
        this.showMigrationDialog = true;
        this.statusMessage = '';
        return;
      }
      const parsed = parseOtpUri(uri);
      this.editor = parsed.authenticator;
      this.digitsText = String(parsed.authenticator.digits);
      this.periodText = String(parsed.authenticator.period);
      this.counterText = String(parsed.authenticator.counter);
      this.editingId = '';
      this.uriText = '';
      this.showEditor = true;
      this.statusMessage = parsed.pinRequiredLength > 0
        ? `已识别账号，请补充 ${parsed.pinRequiredLength} 位 PIN。`
        : '已识别账号，请检查信息后保存。';
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async chooseBackupFile(): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    this.isBackupBusy = true;
    this.busyMessage = '正在选择备份文件…';
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      const documentPicker = new picker.DocumentViewPicker(this.context);
      const uris = await documentPicker.select({
        fileSuffixFilters: ['funbackup', 'authpro'],
        maxSelectNumber: 1
      });
      if (uris.length === 0) {
        return;
      }
      this.pendingBackupUri = uris[0];
      this.backupAction = 'import';
      this.password = '';
      this.showPasswordDialog = true;
      this.statusMessage = '';
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      this.isBackupBusy = false;
      this.busyMessage = '';
    }
  }

  private async chooseStratumFile(): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    this.isBackupBusy = true;
    this.busyMessage = '正在选择 Stratum 备份…';
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      const documentPicker = new picker.DocumentViewPicker(this.context);
      const uris = await documentPicker.select({
        fileSuffixFilters: ['stratum', 'json'],
        maxSelectNumber: 1
      });
      if (uris.length === 0) {
        return;
      }
      this.pendingBackupUri = uris[0];
      this.backupAction = 'stratumImport';
      this.password = '';
      this.showPasswordDialog = true;
      this.statusMessage = '';
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      this.isBackupBusy = false;
      this.busyMessage = '';
    }
  }

  private async chooseExternalImport(format: ExternalImportFormat): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    let uri = '';
    this.isBackupBusy = true;
    this.busyMessage = '正在选择导入文件…';
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      const documentPicker = new picker.DocumentViewPicker(this.context);
      const uris = await documentPicker.select({ maxSelectNumber: 1 });
      if (uris.length === 0) {
        return;
      }
      uri = uris[0];
      this.pendingExternalImportFormat = format;
      this.pendingExternalImportUri = uri;
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
      return;
    } finally {
      this.isBackupBusy = false;
      this.busyMessage = '';
    }

    const option = EXTERNAL_IMPORT_OPTIONS.find((item) => item.format === format);
    if (option === undefined) {
      this.statusMessage = 'The selected import format is not supported.';
      return;
    }
    if (option.passwordPolicy === 'always') {
      this.backupAction = 'externalImport';
      this.password = '';
      this.statusMessage = '';
      this.showPasswordDialog = true;
      return;
    }
    await this.runExternalImport(uri, format, '', option.passwordPolicy === 'maybe');
  }

  private async runExternalImport(uri: string, format: ExternalImportFormat, password: string,
    promptOnMissingPassword: boolean): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    if (uri.length === 0) {
      this.statusMessage = 'Choose an import file first.';
      return;
    }
    this.isBackupBusy = true;
    this.busyMessage = `正在读取 ${labelForFormat(format)} 备份…`;
    let bytes: Uint8Array | null = null;
    try {
      if (this.store === null) {
        throw new Error('The local data store is not ready yet.');
      }
      bytes = this.readFile(uri, 32 * 1024 * 1024, 'import file');
      const converted = await convertExternalBackup(format, bytes, password, this.context ?? undefined);
      const currentSecrets = new Set<string>(this.vault.authenticators.map((item) => item.secret));
      let newAccounts = 0;
      for (const item of converted.vault.authenticators) {
        if (!currentSecrets.has(item.secret)) {
          currentSecrets.add(item.secret);
          newAccounts++;
        }
      }
      await this.saveVault(mergeVaults(this.vault, converted.vault));
      this.selectedCategoryId = '';
      this.pendingExternalImportUri = '';
      this.showSuccessToast(`已导入 ${newAccounts} 个新账号，合并 ${converted.vault.authenticators.length - newAccounts} 个重复账号。`);
      if (converted.failures.length > 0) {
        this.statusMessage = `有 ${converted.failures.length} 条记录未能导入：${converted.failures.slice(0, 3).join('；')}`;
      }
    } catch (error) {
      if (promptOnMissingPassword && error instanceof ImportPasswordRequiredError) {
        this.backupAction = 'externalImport';
        this.pendingExternalImportFormat = format;
        this.pendingExternalImportUri = uri;
        this.password = '';
        this.statusMessage = password.length > 0 ? this.errorMessage(error) : '';
        this.showPasswordDialog = true;
      } else {
        this.statusMessage = this.errorMessage(error);
      }
    } finally {
      bytes?.fill(0);
      this.isBackupBusy = false;
      this.busyMessage = '';
    }
  }

  private openExportPasswordDialog(): void {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    this.backupAction = 'export';
    this.password = '';
    this.showPasswordDialog = true;
    this.statusMessage = '';
  }

  private async confirmPassword(): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    if ((this.backupAction === 'export' || this.backupAction === 'externalImport') &&
      this.password.length === 0) {
      this.statusMessage = this.backupAction === 'externalImport'
        ? '请输入来源应用备份密码。' : '请输入备份密码。';
      return;
    }
    const passwordValue = this.password;
    this.password = '';
    this.showPasswordDialog = false;
    if (this.backupAction === 'import') {
      await this.restoreFromBackup(passwordValue);
    } else if (this.backupAction === 'stratumImport') {
      await this.restoreStratumFile(passwordValue);
    } else if (this.backupAction === 'export') {
      await this.exportBackup(passwordValue);
    } else if (this.backupAction === 'externalImport') {
      await this.runExternalImport(this.pendingExternalImportUri, this.pendingExternalImportFormat,
        passwordValue, true);
    }
  }

  private async restoreFromBackup(passwordValue: string): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    this.isBackupBusy = true;
    this.busyMessage = '正在读取并解密备份…';
    let bytes: Uint8Array | null = null;
    try {
      if (this.pendingBackupUri.length === 0) {
        throw new Error('Choose a backup file first.');
      }
      bytes = this.readFile(this.pendingBackupUri);
      this.pendingRestoreVault = await decryptFunBackup(bytes, passwordValue);
      this.showRestoreDialog = true;
      this.statusMessage = '';
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      bytes?.fill(0);
      this.isBackupBusy = false;
      this.busyMessage = '';
    }
  }

  private async restoreStratumFile(passwordValue: string): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    this.isBackupBusy = true;
    this.busyMessage = '正在读取 Stratum 备份…';
    let bytes: Uint8Array | null = null;
    try {
      if (this.pendingBackupUri.length === 0) {
        throw new Error('Choose a Stratum backup file first.');
      }
      bytes = this.readFile(this.pendingBackupUri, 16 * 1024 * 1024, 'Stratum backup');
      this.pendingRestoreVault = await decryptAuthPro(bytes, passwordValue);
      this.showRestoreDialog = true;
      this.statusMessage = '';
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      bytes?.fill(0);
      this.isBackupBusy = false;
      this.busyMessage = '';
    }
  }

  private async acceptRestore(): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    this.isBackupBusy = true;
    this.busyMessage = '正在合并并保存备份…';
    try {
      const merged = mergeVaults(this.vault, this.pendingRestoreVault);
      await this.saveVault(merged);
      this.selectedCategoryId = '';
      this.showRestoreDialog = false;
      this.pendingRestoreVault = emptyVault();
      this.showSuccessToast('备份已合并。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      this.isBackupBusy = false;
      this.busyMessage = '';
    }
  }

  private cancelRestore(): void {
    this.showRestoreDialog = false;
    this.pendingRestoreVault = emptyVault();
  }

  private async exportBackup(passwordValue: string): Promise<void> {
    if (this.isBackupBusy || this.isIconPackBusy) {
      return;
    }
    this.isBackupBusy = true;
    this.busyMessage = '正在生成 FUN 加密备份…';
    let bytes: Uint8Array | null = null;
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      bytes = await encryptFunBackup(this.vault, passwordValue);
      const documentPicker = new picker.DocumentViewPicker(this.context);
      const uris = await documentPicker.save({
        newFileNames: ['fun-authenticator-backup.funbackup'],
        fileSuffixChoices: ['FUN Authenticator encrypted backup|.funbackup']
      });
      if (uris.length === 0) {
        return;
      }
      this.writeFile(uris[0], bytes);
      this.showSuccessToast('FUN 加密备份已保存。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      bytes?.fill(0);
      this.isBackupBusy = false;
      this.busyMessage = '';
    }
  }

  private readFile(uri: string, maximumSize: number = 16 * 1024 * 1024,
    fileType: string = 'backup'): Uint8Array {
    const file = fileIo.openSync(uri, fileIo.OpenMode.READ_ONLY);
    try {
      const stat = fileIo.statSync(file.fd);
      if (stat.size <= 0 || stat.size > maximumSize) {
        throw new Error(`The selected ${fileType} is empty or too large.`);
      }
      const buffer = new ArrayBuffer(stat.size);
      const bytesRead = fileIo.readSync(file.fd, buffer);
      if (bytesRead !== stat.size) {
        throw new Error(`The selected ${fileType} could not be read completely.`);
      }
      return new Uint8Array(buffer);
    } finally {
      fileIo.closeSync(file);
    }
  }

  private writeFile(uri: string, bytes: Uint8Array): void {
    const file = fileIo.openSync(uri, fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.TRUNC);
    try {
      const bytesWritten = fileIo.writeSync(file.fd, bytes.buffer);
      if (bytesWritten !== bytes.length) {
        throw new Error('The backup file could not be written completely.');
      }
    } finally {
      fileIo.closeSync(file);
    }
  }

  private async importIconPack(): Promise<void> {
    if (this.isIconPackBusy || this.isBackupBusy) {
      return;
    }
    this.isIconPackBusy = true;
    this.busyMessage = '正在选择图标包…';
    try {
      if (this.context === null || this.store === null) {
        throw new Error('The application is not ready to import an icon pack.');
      }
      const documentPicker = new picker.DocumentViewPicker(this.context);
      const uris = await documentPicker.select({ maxSelectNumber: 1 });
      if (uris.length === 0) {
        return;
      }
      this.busyMessage = '正在导入图标包…';
      const bytes = this.readFile(uris[0], 32 * 1024 * 1024, 'icon pack');
      let pack: IconPack;
      try {
        pack = parseStratumIconPack(bytes);
      } finally {
        bytes.fill(0);
      }
      const updated = this.iconPacks.filter((item) =>
        item.name.toLocaleLowerCase() !== pack.name.toLocaleLowerCase());
      updated.push(pack);
      await this.store.saveIconPacks(updated);
      this.iconPacks = updated;
      this.showSuccessToast(`已导入 ${pack.icons.length} 个图标。`);
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      this.isIconPackBusy = false;
      this.busyMessage = '';
    }
  }

  private requestIconPackDelete(packName: string): void {
    this.pendingIconPackDeleteName = packName;
    this.showIconPackDeleteDialog = true;
  }

  private async confirmIconPackDelete(): Promise<void> {
    if (this.isIconPackBusy || this.isBackupBusy) {
      return;
    }
    if (this.store === null) {
      this.statusMessage = 'The local data store is not ready yet.';
      return;
    }
    this.isIconPackBusy = true;
    this.busyMessage = '正在删除图标包…';
    try {
      const updated = this.iconPacks.filter((item) => item.name !== this.pendingIconPackDeleteName);
      await this.store.saveIconPacks(updated);
      this.iconPacks = updated;
      this.showIconPackDeleteDialog = false;
      this.pendingIconPackDeleteName = '';
      this.showSuccessToast('图标包已删除，已使用的图标会保留。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      this.isIconPackBusy = false;
      this.busyMessage = '';
    }
  }

  private async openIconPackWebsite(url: string = 'https://stratumauth.com/icon-packs'): Promise<void> {
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      if (!url.startsWith('https://') && !url.startsWith('http://')) {
        throw new Error('This icon-pack source is not a valid web address.');
      }
      await this.context.startAbility({ action: 'ohos.want.action.viewData', uri: url });
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async openPrivacyPolicy(): Promise<void> {
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      await this.context.startAbility({
        action: 'ohos.want.action.viewData',
        uri: 'https://agreement-drcn.hispace.dbankcloud.cn/index.html?lang=zh&agreementId=2092872494661817600'
      });
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private openIconPicker(item: AuthenticatorRecord): void {
    this.iconPickerAuthenticatorId = item.id;
    this.selectedIconPackName = '';
    this.iconSearchText = '';
    this.statusMessage = '';
    this.showIconPicker = true;
  }

  private openQrCode(item: AuthenticatorRecord): void {
    try {
      this.qrUri = authenticatorUri(item);
      this.accountMenuId = '';
      this.statusMessage = '';
      this.showQrCodeDialog = true;
    } catch (error) {
      this.accountMenuId = '';
      this.statusMessage = this.errorMessage(error);
    }
  }

  private closeQrCode(): void {
    this.showQrCopyWarning = false;
    this.showQrCodeDialog = false;
    this.qrUri = '';
  }

  private async copyQrUri(): Promise<void> {
    try {
      const data = pasteboard.createData('text/plain', this.qrUri);
      await pasteboard.getSystemPasteboard().setData(data);
      this.showQrCopyWarning = false;
      this.showSuccessToast('URI 已复制，请妥善保管。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private selectedIconEntries(): Array<IconPackEntry> {
    const pack = this.iconPacks.find((item) => item.name === this.selectedIconPackName);
    const query = this.iconSearchText.trim().toLocaleLowerCase();
    return pack === undefined ? [] : pack.icons.filter((item) =>
      query.length === 0 || item.name.toLocaleLowerCase().includes(query));
  }

  private iconImageSource(data: string): string {
    const subtype = data.startsWith('iVBORw0KGgo') ? 'png' :
      data.startsWith('/9j/') ? 'jpeg' :
      data.startsWith('UklGR') ? 'webp' :
        data.startsWith('Qk') ? 'bmp' :
          data.startsWith('AAAAAGZ0eXB') || data.startsWith('AAAAGGZ0eXB') ? 'heif' : '';
    if (subtype.length === 0) {
      throw new Error('The selected file is not a supported image.');
    }
    return `data:image/${subtype};base64,${data}`;
  }

  private async assignDefaultIcon(iconKey: string): Promise<void> {
    if (!isDefaultIconKey(iconKey)) {
      this.statusMessage = 'The selected default icon is not available.';
      return;
    }
    await this.saveAccountIcon(iconKey);
  }

  private async assignCustomIcon(data: string): Promise<void> {
    await this.saveAccountIcon(`@${this.customIconId(data)}`, data);
  }

  private async saveAccountIcon(iconValue: string, customIconData?: string,
    successMessage: string = '图标已更新。'): Promise<void> {
    try {
      const item = this.vault.authenticators.find((current) =>
        current.id === this.iconPickerAuthenticatorId);
      if (item === undefined) {
        throw new Error('The selected authenticator no longer exists.');
      }
      const authenticators = this.vault.authenticators.map((current) => {
        const copy = copyAuthenticator(current);
        if (copy.id === item.id) {
          copy.icon = iconValue;
        }
        return copy;
      });
      const updated = copyVault(this.vault, authenticators);
      if (customIconData !== undefined) {
        const id = iconValue.substring(1);
        if (!updated.customIcons.some((icon) => icon.id === id)) {
          updated.customIcons.push({ id, data: customIconData });
        }
      }
      await this.saveVault(updated);
      this.showIconPicker = false;
      this.iconPickerAuthenticatorId = '';
      this.showSuccessToast(successMessage);
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async resetAccountIcon(): Promise<void> {
    await this.saveAccountIcon('', undefined, '已恢复默认图标。');
  }

  private async importCustomIconForAccount(): Promise<void> {
    if (this.isIconPackBusy || this.isBackupBusy) {
      return;
    }
    this.isIconPackBusy = true;
    this.busyMessage = '正在选择图片…';
    try {
      if (this.context === null) {
        throw new Error('Unable to access the application context.');
      }
      const documentPicker = new picker.DocumentViewPicker(this.context);
      const uris = await documentPicker.select({
        fileSuffixFilters: ['png', 'jpg', 'jpeg', 'webp', 'bmp'],
        maxSelectNumber: 1
      });
      if (uris.length === 0) {
        return;
      }
      this.busyMessage = '正在读取图片…';
      const bytes = this.readFile(uris[0], 10 * 1024 * 1024, 'image');
      try {
        const data = this.base64Helper.encodeToStringSync(bytes);
        this.iconImageSource(data);
        await this.assignCustomIcon(data);
      } finally {
        bytes.fill(0);
      }
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    } finally {
      this.isIconPackBusy = false;
      this.busyMessage = '';
    }
  }

  private requestDelete(item: AuthenticatorRecord): void {
    this.pendingDeleteId = item.id;
    this.accountMenuId = '';
    this.showDeleteDialog = true;
  }

  private async confirmDelete(): Promise<void> {
    try {
      const authenticators: Array<AuthenticatorRecord> = [];
      for (const item of this.vault.authenticators) {
        if (item.id !== this.pendingDeleteId) {
          const copy = copyAuthenticator(item);
          copy.ranking = authenticators.length;
          authenticators.push(copy);
        }
      }
      await this.saveVault(copyVault(this.vault, authenticators));
      this.showDeleteDialog = false;
      this.showSuccessToast('账号已删除。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private newMigrationAccountCount(): number {
    let count = 0;
    for (const item of this.pendingMigrationAccounts) {
      if (!this.vault.authenticators.some((existing) => existing.secret === item.secret)) {
        count++;
      }
    }
    return count;
  }

  private async acceptMigration(): Promise<void> {
    try {
      const records: Array<AuthenticatorRecord> = [];
      const knownSecrets = new Set<string>();
      for (const item of this.vault.authenticators) {
        const copy = copyAuthenticator(item);
        records.push(copy);
        knownSecrets.add(copy.secret);
      }
      let added = 0;
      for (const item of this.pendingMigrationAccounts) {
        if (!knownSecrets.has(item.secret)) {
          const copy = copyAuthenticator(item);
          copy.ranking = records.length;
          records.push(copy);
          knownSecrets.add(copy.secret);
          added++;
        }
      }
      if (added === 0) {
        this.showSuccessToast('二维码中的账号已全部存在。');
      } else {
        await this.saveVault(copyVault(this.vault, records));
        this.showSuccessToast(`已导入 ${added} 个账号，重复密钥已跳过。`);
      }
      this.showMigrationDialog = false;
      this.showEditor = false;
      this.pendingMigrationAccounts = [];
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private cancelMigration(): void {
    this.showMigrationDialog = false;
    this.pendingMigrationAccounts = [];
  }

  private errorMessage(error: Object): string {
    if (error instanceof Error && error.message.length > 0) {
      return error.message;
    }
    return '操作失败，请检查输入或设备权限后重试。';
  }

  private countdownPeriod(item: AuthenticatorRecord): number {
    if (item.type === 'mOTP') {
      return 30;
    }
    if (item.type === 'Steam' || item.type === 'Yandex') {
      return 30;
    }
    return item.period;
  }

  private countdownPercent(item: AuthenticatorRecord): number {
    if (item.type === 'HOTP') {
      return 100;
    }
    const period = this.countdownPeriod(item);
    return Math.max(0, Math.min(100, ((period - (this.nowSeconds % period)) / period) * 100));
  }

  private accountCode(item: AuthenticatorRecord): string {
    return computeOtp(item, this.nowSeconds);
  }

  private groupedCode(item: AuthenticatorRecord): string {
    const code = this.accountCode(item);
    if (this.codeGroupSize === 0) {
      return code;
    }
    const groupSize = this.codeGroupSize > 0 ? this.codeGroupSize :
      Math.ceil(code.length / (this.codeGroupSize === -2 ? 2 : 3));
    const groups: Array<string> = [];
    for (let index = 0; index < code.length; index += groupSize) {
      groups.push(code.substring(index, Math.min(index + groupSize, code.length)));
    }
    return groups.join(' ');
  }

  private async assignCategory(item: AuthenticatorRecord, categoryId: string): Promise<void> {
    const authenticators = this.vault.authenticators.map((current: AuthenticatorRecord) => {
      const copy = copyAuthenticator(current);
      if (copy.id === item.id) {
        copy.categoryId = categoryId;
      }
      return copy;
    });
    try {
      await this.saveVault(copyVault(this.vault, authenticators));
      this.categoryAssignmentId = '';
      this.accountMenuId = '';
      this.showSuccessToast('分类已更新。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private async createCategoryForAssignment(item: AuthenticatorRecord): Promise<void> {
    const name = this.assignmentCategoryName.trim();
    if (name.length === 0) {
      this.statusMessage = '请输入分类名称。';
      return;
    }
    if (this.vault.categories.some((category) => category.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
      this.statusMessage = '该分类已存在。';
      return;
    }
    const category: AuthenticatorCategory = {
      id: categoryIdForName(name),
      name,
      ranking: this.vault.categories.length
    };
    const categories = this.vault.categories.concat([category]);
    const authenticators = this.vault.authenticators.map((current: AuthenticatorRecord) => {
      const copy = copyAuthenticator(current);
      if (copy.id === item.id) {
        copy.categoryId = category.id;
      }
      return copy;
    });
    try {
      await this.saveVault(copyVault(this.vault, authenticators, categories));
      this.assignmentCategoryName = '';
      this.categoryAssignmentId = '';
      this.showSuccessToast('分类已添加并指定。');
    } catch (error) {
      this.statusMessage = this.errorMessage(error);
    }
  }

  private sortOptions(): Array<SortOption> {
    return [
      { mode: 'az', label: '字母顺序（A 至 Z）' },
      { mode: 'za', label: '字母顺序（Z 至 A）' },
      { mode: 'mostCopied', label: '复制次数（递减）' },
      { mode: 'leastCopied', label: '复制次数（递增）' },
      { mode: 'custom', label: '自定义' }
    ];
  }

  private isCustomSortMode(): boolean {
    return this.sortMode === 'custom';
  }

  private viewModeLabel(): string {
    switch (this.viewMode) {
      case 'compact':
        return '紧凑';
      case 'tile':
        return '平铺';
      default:
        return '默认';
    }
  }

  private codeGroupLabel(): string {
    switch (this.codeGroupSize) {
      case 0:
        return '不分组';
      case 2:
        return '每两位';
      case 4:
        return '每四位';
      case -2:
        return '分为两组';
      case -3:
        return '分为三组';
      default:
        return '每三位';
    }
  }

  private nextCodeGroupSize(): number {
    switch (this.codeGroupSize) {
      case 0:
        return 2;
      case 2:
        return 3;
      case 3:
        return 4;
      case 4:
        return -2;
      case -2:
        return -3;
      default:
        return 0;
    }
  }

  @Builder
  private header() {
    Row({ space: 12 }) {
      if (this.searchVisible) {
        TextInput({ placeholder: '搜索', text: this.searchText })
          .layoutWeight(1)
          .fontSize(18)
          .backgroundColor('transparent')
          .fontColor(this.primaryTextColor())
          .onChange((value: string) => this.searchText = value);
        Button('×')
          .width(40)
          .height(40)
          .padding(0)
          .fontSize(24)
          .backgroundColor('transparent')
          .fontColor(this.primaryTextColor())
          .onClick(() => this.closeSearch());
      } else {
        Text(this.titleForCategory())
          .fontSize(20)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .layoutWeight(1)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis });
        Button() {
          Image($rawfile('search.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
        }
          .width(40)
          .height(40)
          .backgroundColor('transparent')
          .onClick(() => {
            this.searchVisible = true;
            this.searchText = '';
          });
        Button() {
          Image($rawfile('filter.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
        }
          .width(40)
          .height(40)
          .backgroundColor('transparent')
          .onClick(() => this.showSortMenu = true);
      }
    }
    .width('100%')
    .height(56)
    .padding({ left: 16, right: 8 })
    .backgroundColor(this.surfaceColor());
  }

  private closeSearch(): void {
    this.searchVisible = false;
    this.searchText = '';
  }

  @Builder
  private authenticatorIcon(item: AuthenticatorRecord, size: number) {
    if (this.customIconSource(item.icon).length > 0) {
      Image(this.customIconSource(item.icon))
        .width(size)
        .height(size);
    } else if (item.icon.length > 0 && !item.icon.startsWith('@') && !isDefaultIconKey(item.icon)) {
      Text(item.icon.substring(0, 1).toUpperCase())
        .fontSize(size * 0.65)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.primaryTextColor());
    } else {
      Image(this.defaultIconSource(this.defaultIconKey(item)))
        .width(size)
        .height(size);
    }
  }

  @Builder
  private authenticatorCard(item: AuthenticatorRecord) {
    if (this.viewMode === 'tile') {
    Column({ space: 6 }) {
      Row() {
        this.authenticatorIcon(item, 32);
        Blank();
        Button() {
          Image($rawfile('more.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
        }
          .width(36)
          .height(36)
          .backgroundColor('transparent')
          .onClick(() => this.accountMenuId = item.id);
        }
      .width('100%')
      Text(item.issuer)
        .width('100%')
        .fontSize(14)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.primaryTextColor())
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis });
      if (this.showUsernames && item.username.length > 0) {
        Text(item.username)
          .width('100%')
          .fontSize(12)
          .fontColor(this.secondaryTextColor())
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis });
      }
      Text(this.groupedCode(item))
        .width('100%')
        .fontSize(22)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.primaryTextColor());
      if (item.type !== 'HOTP') {
        Row() {
          Row()
            .width(`${this.countdownPercent(item)}%`)
            .height(2)
            .backgroundColor(this.primaryColor());
        }
        .width('100%')
        .height(2)
        .backgroundColor(this.darkMode ? '#3A4046' : '#DDE3EA');
      }
    }
    .width('100%')
    .padding({ left: 14, right: 14, top: 10, bottom: 0 })
    .alignItems(HorizontalAlign.Start)
    .justifyContent(FlexAlign.Start)
    .backgroundColor(this.surfaceColor())
    .borderRadius(8)
    .border({ width: 0.5, color: this.darkMode ? '#353A40' : '#D9DDE2', radius: 8 })
    .clip(true)
    .onClick(() => {
      if (this.tapToCopy) {
        this.copyCode(item);
      }
    });
    } else if (this.viewMode === 'compact') {
    Column() {
      Row({ space: 8 }) {
        Column() {
          this.authenticatorIcon(item, 24);
        }
        .width(32)
        .height(32)
        .justifyContent(FlexAlign.Center);
        Column({ space: 2 }) {
          Text(item.issuer)
            .fontSize(14)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.primaryTextColor())
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis });
          if (this.showUsernames && item.username.length > 0) {
            Text(item.username)
              .fontSize(11)
              .fontColor(this.secondaryTextColor())
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis });
          }
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1);
        Text(this.groupedCode(item))
          .fontSize(18)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor());
        Button() {
          Image($rawfile('more.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
        }
          .width(32)
          .height(32)
          .backgroundColor('transparent')
          .onClick(() => this.accountMenuId = item.id);
      }
      .width('100%')
      if (item.type !== 'HOTP') {
        Row() {
          Row()
            .width(`${this.countdownPercent(item)}%`)
            .height(2)
            .backgroundColor(this.primaryColor());
        }
        .width('100%')
        .height(2)
        .backgroundColor(this.darkMode ? '#3A4046' : '#DDE3EA')
        .margin({ top: 6 });
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
    .justifyContent(FlexAlign.Start)
    .padding({ left: 16, right: 8, top: 8, bottom: 8 })
    .backgroundColor(this.surfaceColor())
    .borderRadius(8)
    .border({ width: 0.5, color: this.darkMode ? '#353A40' : '#D9DDE2', radius: 8 })
    .clip(true)
    .onClick(() => {
      if (this.tapToCopy) {
        this.copyCode(item);
      }
    });
    } else {
    Column() {
      Row({ space: 12 }) {
        Column() {
          this.authenticatorIcon(item, 32);
        }
        .width(32)
        .height(32)
        .justifyContent(FlexAlign.Center)
        .alignItems(HorizontalAlign.Center);
        Column({ space: 1 }) {
          Text(item.issuer)
            .fontSize(16)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.primaryTextColor())
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis });
          if (this.showUsernames && item.username.length > 0) {
            Text(item.username)
              .fontSize(14)
              .fontColor(this.secondaryTextColor())
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis });
          }
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1);
        Button() {
          Image($rawfile('more.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
        }
          .width(32)
          .height(32)
          .backgroundColor('transparent')
          .onClick(() => this.accountMenuId = item.id);
      }
      .width('100%')
      .padding({ left: 32, right: 18, top: 16 });
      Row() {
        Text(this.groupedCode(item))
          .fontSize(36)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .letterSpacing(1);
        Blank();
        if (item.type === 'HOTP') {
          Button('↻')
            .width(36)
            .height(36)
            .fontSize(22)
            .backgroundColor('transparent')
            .fontColor(this.primaryTextColor())
            .onClick(() => this.copyCode(item));
        }
      }
      .width('100%')
      .padding({ left: 76, right: 20, top: 2, bottom: 10 });
      if (item.type !== 'HOTP') {
        Row() {
          Row()
            .width(`${this.countdownPercent(item)}%`)
            .height(2)
            .backgroundColor(this.primaryColor());
        }
        .width('100%')
        .height(2)
        .backgroundColor(this.darkMode ? '#3A4046' : '#DDE3EA');
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
    .justifyContent(FlexAlign.Start)
    .backgroundColor(this.surfaceColor())
    .borderRadius(8)
    .border({ width: 0.5, color: this.darkMode ? '#353A40' : '#D9DDE2', radius: 8 })
    .clip(true)
    .onClick(() => {
      if (this.tapToCopy) {
        this.copyCode(item);
      }
    });
    }
  }

  private typeLabel(type: AuthenticatorType): string {
    switch (type) {
      case 'HOTP':
        return '基于计数器（HOTP）';
      case 'mOTP':
        return 'Mobile-OTP';
      case 'Steam':
        return 'Steam Guard';
      case 'Yandex':
        return 'Yandex OTP';
      default:
        return '基于时间（TOTP）';
    }
  }

  @Builder
  private homeContent() {
    Column() {
      if (this.statusMessage.length > 0) {
        Text(this.statusMessage)
          .fontSize(13)
          .fontColor(this.statusMessage.includes('失败') || this.statusMessage.includes('错误')
            ? (this.darkMode ? '#FFB4AB' : '#BA1A1A') : this.secondaryTextColor())
          .padding({ left: 16, right: 16, bottom: 6 });
      }
      if (this.visibleAuthenticators().length === 0) {
        Column({ space: 12 }) {
          Text('◉')
            .fontSize(48)
            .fontColor(this.secondaryTextColor());
          Text(this.vault.authenticators.length === 0 ? '还没有账号' : '没有找到匹配账号')
            .fontSize(24)
            .fontWeight(FontWeight.Regular)
            .fontColor(this.primaryTextColor());
          Text(this.vault.authenticators.length === 0
            ? '如果您是第一次使用，请从下方开始添加，或导入现有验证器。'
            : '试试其他搜索内容或分类。')
            .fontSize(14)
            .fontColor(this.secondaryTextColor())
            .textAlign(TextAlign.Center);
          if (this.vault.authenticators.length === 0) {
            Button('入门指南')
              .fontSize(14)
              .fontColor(this.primaryColor())
              .backgroundColor('transparent')
                .onClick(() => this.openGuide());
            Button('从其他应用导入')
              .height(44)
              .fontSize(14)
              .fontColor(this.primaryColor())
              .backgroundColor('transparent')
              .border({ width: 1, color: this.primaryColor(), radius: 8 })
              .onClick(() => this.showImportMenu = true);
            Button('从备份中恢复')
              .height(44)
              .fontSize(14)
              .fontColor(this.primaryColor())
              .backgroundColor('transparent')
              .border({ width: 1, color: this.primaryColor(), radius: 8 })
              .onClick(() => this.chooseBackupFile());
          }
        }
        .layoutWeight(1)
        .width('100%')
        .justifyContent(FlexAlign.Center)
        .padding({ left: 32, right: 32, top: 20, bottom: 24 });
      } else if (this.viewMode === 'tile') {
        Grid() {
          ForEach(this.visibleAuthenticators(), (item: AuthenticatorRecord) => {
            GridItem() {
              this.authenticatorCard(item);
            }
          }, (item: AuthenticatorRecord) => `${item.id}-${item.icon}-${item.issuer}`);
        }
        .columnsTemplate('1fr 1fr')
        .columnsGap(8)
        .rowsGap(8)
        .layoutWeight(1)
        .width('100%')
        .padding({ left: 14, right: 14, top: 8, bottom: 12 })
        .scrollBar(BarState.Auto);
      } else {
        Scroll() {
          Column({ space: this.viewMode === 'compact' ? 4 : 8 }) {
            ForEach(this.visibleAuthenticators(), (item: AuthenticatorRecord) => {
              this.authenticatorCard(item);
            }, (item: AuthenticatorRecord) => item.type === 'HOTP'
              ? `${item.id}-${item.counter}-${item.icon}-${item.issuer}`
              : `${item.id}-${item.icon}-${item.issuer}`);
          }
          .width('100%')
          .constraintSize({ minHeight: '100%' })
          .alignItems(HorizontalAlign.Start)
          .justifyContent(FlexAlign.Start)
          .padding({ left: 14, right: 14, top: 8, bottom: 12 });
        }
        .layoutWeight(1)
        .scrollBar(BarState.Auto);
      }
    }
    .layoutWeight(1)
    .alignItems(HorizontalAlign.Start)
    .justifyContent(FlexAlign.Start)
    .width('100%');
  }

  @Builder
  private bottomBar() {
    Row() {
      Button() {
        Column() {
          Image($rawfile('filter.svg'))
            .width(26)
            .height(26)
            .fillColor(this.selectedCategoryId.length === 0 ? this.primaryColor() : this.primaryTextColor())
            .supportSvg2(true);
        }
        .justifyContent(FlexAlign.Center)
        .alignItems(HorizontalAlign.Center);
      }
        .layoutWeight(1)
        .height(64)
        .padding(0)
        .backgroundColor('transparent')
        .onClick(() => this.showCategoryMenu = true);
      Button('+')
        .width(56)
        .height(56)
        .fontSize(36)
        .backgroundColor(this.primaryColor())
        .fontColor('#FFFFFF')
        .borderRadius(16)
        .onClick(() => this.showAddMenu = true)
        .layoutWeight(1);
      Button() {
        Column() {
          Image($rawfile('menu.svg'))
            .width(26)
            .height(26)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
        }
        .justifyContent(FlexAlign.Center)
        .alignItems(HorizontalAlign.Center);
      }
        .layoutWeight(1)
        .height(64)
        .padding(0)
        .backgroundColor('transparent')
        .onClick(() => this.showMainMenu = true);
    }
    .width('100%')
    .height(84)
    .padding({ left: 12, right: 12, top: 6, bottom: 6 })
    .backgroundColor(this.surfaceColor());
  }

  @Builder
  private sheetHandle() {
    Row()
      .width(32)
      .height(4)
      .backgroundColor(this.darkMode ? '#737A82' : '#444B50')
      .borderRadius(2)
      .margin({ top: 10, bottom: 18 });
  }

  @Builder
  private mainMenuSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showMainMenu = false);
      Column({ space: 4 }) {
        this.sheetHandle();
        Text('菜单')
          .width('100%')
          .fontSize(20)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 8 });
        Row({ space: 20 }) {
          Text('▣').fontSize(24).fontColor(this.primaryTextColor());
          Text('备份').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(52)
        .onClick(() => {
          this.showMainMenu = false;
          this.showSettings = true;
          this.settingsPage = 'backup';
        });
        Row({ space: 20 }) {
          Text('◈').fontSize(24).fontColor(this.primaryTextColor());
          Text('分类').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(52)
        .onClick(() => {
          this.showMainMenu = false;
          this.showSettings = true;
          this.settingsPage = 'categories';
        });
        Row({ space: 20 }) {
          Text('▦').fontSize(24).fontColor(this.primaryTextColor());
          Text('图标包').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(52)
        .onClick(() => {
          this.showMainMenu = false;
          this.showSettings = true;
          this.settingsPage = 'icons';
        });
        Row({ space: 20 }) {
          Text('⚙').fontSize(24).fontColor(this.primaryTextColor());
          Text('设置').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(52)
        .onClick(() => {
          this.showMainMenu = false;
          this.showSettings = true;
          this.settingsPage = 'main';
        });
        Row({ space: 20 }) {
          Image($rawfile('guide.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
          Text('入门指南').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(52)
        .onClick(() => {
          this.showMainMenu = false;
          this.openGuide();
        });
      }
      .width('100%')
      .height('56%')
      .padding({ left: 20, right: 20, bottom: 12 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private categoryMenuSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showCategoryMenu = false);
      Column() {
        this.sheetHandle();
        Text('选择分类')
          .width('100%')
          .fontSize(20)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 8 });
        Scroll() {
          Column({ space: 4 }) {
            Row() {
              Text('全部')
                .fontSize(16)
                .fontColor(this.selectedCategoryId.length === 0 ? this.primaryColor() : this.primaryTextColor())
                .layoutWeight(1);
              if (this.selectedCategoryId.length === 0) {
                Text('✓').fontSize(18).fontColor(this.primaryColor());
              }
            }
            .width('100%')
            .height(48)
            .padding({ left: 12, right: 12 })
            .backgroundColor(this.selectedCategoryId.length === 0 ? this.accentSoftColor() : 'transparent')
            .borderRadius(8)
            .onClick(() => {
              this.selectedCategoryId = '';
              this.showCategoryMenu = false;
            });
            ForEach(this.vault.categories, (category: AuthenticatorCategory) => {
              Row() {
                Text(category.name)
                  .fontSize(16)
                  .fontColor(this.selectedCategoryId === category.id ? this.primaryColor() : this.primaryTextColor())
                  .layoutWeight(1);
                if (this.selectedCategoryId === category.id) {
                  Text('✓').fontSize(18).fontColor(this.primaryColor());
                }
              }
              .width('100%')
              .height(48)
              .padding({ left: 12, right: 12 })
              .backgroundColor(this.selectedCategoryId === category.id ? this.accentSoftColor() : 'transparent')
              .borderRadius(8)
              .onClick(() => {
                this.selectedCategoryId = category.id;
                this.showCategoryMenu = false;
              });
            }, (category: AuthenticatorCategory) => category.id);
          }
          .width('100%')
          .justifyContent(FlexAlign.Start)
          .alignItems(HorizontalAlign.Start)
        }
        .layoutWeight(1)
        .width('100%')
        .scrollBar(BarState.Auto)
        .scrollable(ScrollDirection.Vertical)
        .initialOffset({ xOffset: 0, yOffset: 0 })
        .align(Alignment.TopStart);
      }
      .width('100%')
      .height('56%')
      .justifyContent(FlexAlign.Start)
      .alignItems(HorizontalAlign.Start)
      .padding({ left: 20, right: 20, bottom: 12 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private addMenuSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showAddMenu = false);
      Column() {
        this.sheetHandle();
        Text('添加')
          .width('100%')
          .fontSize(24)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 12 });
        Row({ space: 20 }) {
          Image($rawfile('qr-code.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
          Text('扫描二维码').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(56)
        .onClick(() => {
          this.showAddMenu = false;
          this.scanOtpUri();
        });
        Row({ space: 20 }) {
          Image($rawfile('key.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
          Text('输入密钥').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(56)
        .onClick(() => {
          this.showAddMenu = false;
          this.openNewEditor();
        });
        Row({ space: 20 }) {
          Image($rawfile('uri.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
          Text('输入 URI').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(56)
        .onClick(() => {
          this.showAddMenu = false;
          this.openUriEditor();
        });
        Row({ space: 20 }) {
          Image($rawfile('restore.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
          Text('恢复备份').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(56)
        .onClick(() => {
          this.showAddMenu = false;
          this.chooseBackupFile();
        });
        Row({ space: 20 }) {
          Image($rawfile('apps.svg'))
            .width(24)
            .height(24)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
          Text('从其他应用导入').fontSize(18).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(56)
        .onClick(() => {
          this.showAddMenu = false;
          this.showImportMenu = true;
        });
      }
      .width('100%')
      .padding({ left: 20, right: 20, bottom: 16 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private importMenuSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showImportMenu = false);
      Column() {
        this.sheetHandle();
        Text('从其他应用导入')
          .width('100%')
          .fontSize(22)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 12 });
        Row({ space: 16 }) {
          Image($rawfile('stratum-logo.png')).width(32).height(32);
          Text('导入 Stratum 文件').fontSize(16).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(56)
        .padding({ left: 4, right: 4 })
        .onClick(() => {
          this.showImportMenu = false;
          this.chooseStratumFile();
        });
        Row({ space: 16 }) {
          Image($rawfile('uri-list.svg'))
            .width(28)
            .height(28)
            .fillColor(this.primaryTextColor())
            .supportSvg2(true);
          Text('导入 URI list 文本').fontSize(16).fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height(56)
        .padding({ left: 4, right: 4 })
        .onClick(() => {
          this.showImportMenu = false;
          this.chooseExternalImport('uri-list');
        });
      }
      .width('100%')
      .height('40%')
      .padding({ left: 20, right: 20, bottom: 16 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private sortMenu() {
    Column() {
      Row() {
        Blank().layoutWeight(1).onClick(() => this.showSortMenu = false);
        Column({ space: 0 }) {
          ForEach(this.sortOptions(), (option: SortOption) => {
            Row() {
              Text(option.label)
                .fontSize(16)
                .fontColor(this.primaryTextColor())
                .layoutWeight(1);
              Text(this.sortMode === option.mode ? '◉' : '○')
                .fontSize(20)
                .fontColor(this.sortMode === option.mode ? this.primaryColor() : this.secondaryTextColor());
            }
            .width(226)
            .height(48)
            .padding({ left: 16, right: 16 })
            .onClick(() => {
              this.showSortMenu = false;
              this.saveAppPreferences(this.viewMode, option.mode);
            });
          }, (option: SortOption) => option.mode);
          Row().width('100%').height(1).backgroundColor(this.darkMode ? '#454A50' : '#DDE3EA');
          Row() {
            Text(this.lockOrdering ? '解锁排序' : '锁定排序')
              .fontSize(16)
              .fontColor(this.primaryTextColor())
              .layoutWeight(1);
            Text(this.lockOrdering ? '✓' : '')
              .fontSize(20)
              .fontColor(this.primaryColor());
          }
          .width('100%')
          .height(48)
          .padding({ left: 16, right: 16 })
          .onClick(() => {
            this.showSortMenu = false;
            this.saveAppPreferences(this.viewMode, this.sortMode, this.codeGroupSize,
              this.showUsernames, this.tapToCopy, !this.lockOrdering);
          });
        }
        .width(226)
        .padding({ top: 4, bottom: 4 })
        .backgroundColor(this.darkMode ? '#292D32' : '#E9EFF7')
        .borderRadius(4)
        .shadow({ radius: 10, color: '#33000000', offsetX: 0, offsetY: 3 });
      }
      .width('100%')
      .padding({ top: 10, right: 4 });
      Blank().layoutWeight(1).onClick(() => this.showSortMenu = false);
    }
    .width('100%')
    .height('100%');
  }

  @Builder
  private accountMenuSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.accountMenuId = '');
      Column() {
        this.sheetHandle();
        Text('编辑')
          .width('100%')
          .fontSize(24)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 12 });
        ForEach(this.vault.authenticators.filter((item: AuthenticatorRecord) => item.id === this.accountMenuId),
          (item: AuthenticatorRecord) => {
            Row({ space: 20 }) {
              Text('✎').fontSize(24).fontColor(this.primaryTextColor());
              Text('编辑详情').fontSize(18).fontColor(this.primaryTextColor());
            }
            .width('100%')
            .height(56)
            .onClick(() => {
              this.accountMenuId = '';
              this.openEditEditor(item);
            });
            Row({ space: 20 }) {
              Text('▧').fontSize(24).fontColor(this.primaryTextColor());
              Text('更改图标').fontSize(18).fontColor(this.primaryTextColor());
            }
            .width('100%')
            .height(56)
            .onClick(() => {
              this.accountMenuId = '';
              this.openIconPicker(item);
            });
            Row({ space: 20 }) {
              Text('◈').fontSize(24).fontColor(this.primaryTextColor());
              Text('指定分类').fontSize(18).fontColor(this.primaryTextColor());
            }
            .width('100%')
            .height(56)
            .onClick(() => {
              this.assignmentCategoryName = '';
              this.categoryAssignmentId = item.id;
              this.accountMenuId = '';
            });
            Row({ space: 20 }) {
              Text('▦').fontSize(24).fontColor(this.primaryTextColor());
              Text('显示二维码').fontSize(18).fontColor(this.primaryTextColor());
            }
            .width('100%')
            .height(56)
            .onClick(() => {
              this.accountMenuId = '';
              this.openQrCode(item);
            });
            if (this.sortMode === 'custom') {
              Row({ space: 20 }) {
                Text('↕').fontSize(24).fontColor(this.primaryTextColor());
                Text('调整顺序').fontSize(18).fontColor(this.primaryTextColor());
              }
              .width('100%')
              .height(56)
              .onClick(() => {
                this.accountMenuId = '';
                if (this.lockOrdering) {
                  this.statusMessage = '排序已锁定。';
                } else {
                  this.reorderId = item.id;
                }
              });
            }
            Row({ space: 20 }) {
              Text('▤').fontSize(24).fontColor('#BA1A1A');
              Text('删除').fontSize(18).fontColor('#BA1A1A');
            }
            .width('100%')
            .height(56)
            .onClick(() => this.requestDelete(item));
          }, (item: AuthenticatorRecord) => item.id);
      }
      .width('100%')
      .padding({ left: 20, right: 20, bottom: 16 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private reorderSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.reorderId = '');
      Column() {
        this.sheetHandle();
        Text('调整顺序')
          .width('100%')
          .fontSize(22)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 12 });
        ForEach(this.vault.authenticators.filter((item: AuthenticatorRecord) => item.id === this.reorderId),
          (item: AuthenticatorRecord) => {
            Row({ space: 20 }) {
              Text('↑').fontSize(24).fontColor(this.primaryTextColor());
              Text('上移').fontSize(18).fontColor(this.primaryTextColor());
            }
            .width('100%')
            .height(56)
            .onClick(() => {
              this.reorderId = '';
              this.moveAuthenticator(item, -1);
            });
            Row({ space: 20 }) {
              Text('↓').fontSize(24).fontColor(this.primaryTextColor());
              Text('下移').fontSize(18).fontColor(this.primaryTextColor());
            }
            .width('100%')
            .height(56)
            .onClick(() => {
              this.reorderId = '';
              this.moveAuthenticator(item, 1);
            });
          }, (item: AuthenticatorRecord) => item.id);
      }
      .width('100%')
      .padding({ left: 20, right: 20, bottom: 16 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private categoryAssignmentSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.categoryAssignmentId = '');
      Column() {
        this.sheetHandle();
        Text('指定分类')
          .width('100%')
          .fontSize(22)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 12 });
        ForEach(this.vault.authenticators.filter((item: AuthenticatorRecord) => item.id === this.categoryAssignmentId),
          (item: AuthenticatorRecord) => {
            Row({ space: 8 }) {
              TextInput({ placeholder: '新分类名称', text: this.assignmentCategoryName })
                .layoutWeight(1)
                .height(48)
                .fontSize(16)
                .backgroundColor('transparent')
                .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 8 })
                .padding({ left: 12, right: 12 })
                .onChange((value: string) => this.assignmentCategoryName = value);
              Button('添加')
                .height(48)
                .fontSize(14)
                .backgroundColor(this.primaryColor())
                .fontColor('#FFFFFF')
                .borderRadius(8)
                .onClick(() => this.createCategoryForAssignment(item));
            }
            .width('100%')
            .margin({ bottom: 8 });
            Scroll() {
              Column() {
                Row() {
                  Text('未分类')
                    .fontSize(18)
                    .fontColor(this.primaryTextColor())
                    .layoutWeight(1);
                  if (item.categoryId.length === 0) {
                    Text('✓').fontSize(20).fontColor(this.primaryColor());
                  }
                }
                .width('100%')
                .height(52)
                .onClick(() => this.assignCategory(item, ''));
                ForEach(this.vault.categories, (category: AuthenticatorCategory) => {
                  Row() {
                    Text(category.name)
                      .fontSize(18)
                      .fontColor(this.primaryTextColor())
                      .layoutWeight(1);
                    if (item.categoryId === category.id) {
                      Text('✓').fontSize(20).fontColor(this.primaryColor());
                    }
                  }
                  .width('100%')
                  .height(52)
                  .onClick(() => this.assignCategory(item, category.id));
                }, (category: AuthenticatorCategory) => category.id);
              }
              .width('100%')
              .alignItems(HorizontalAlign.Start)
              .justifyContent(FlexAlign.Start);
            }
            .layoutWeight(1)
            .width('100%')
            .scrollBar(BarState.Auto)
            .scrollable(ScrollDirection.Vertical)
            .initialOffset({ xOffset: 0, yOffset: 0 })
            .align(Alignment.TopStart);
          }, (item: AuthenticatorRecord) => item.id);
      }
      .width('100%')
      .height('62%')
      .padding({ left: 20, right: 20, bottom: 16 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private settingsContent() {
    Column() {
      Row({ space: 16 }) {
        Button('<')
          .width(48)
          .height(48)
          .fontSize(28)
          .padding(0)
          .backgroundColor('transparent')
          .fontColor(this.primaryTextColor())
          .onClick(() => {
            if (this.settingsPage === 'main') {
              this.showSettings = false;
              this.statusMessage = '';
            } else {
              this.settingsPage = 'main';
            }
          });
        Text(this.settingsPage === 'categories' ? '分类' : this.settingsPage === 'backup' ? '备份' :
          this.settingsPage === 'icons' ? '图标包' : '设置')
          .fontSize(22)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor());
      }
      .width('100%')
      .height(56)
      .padding({ left: 16, right: 16 });
      if (this.settingsPage === 'categories') {
        this.categoriesSettingsContent();
      } else if (this.settingsPage === 'backup') {
        this.backupSettingsContent();
      } else if (this.settingsPage === 'icons') {
        this.iconPacksContent();
      } else {
        this.generalSettingsContent();
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor(this.pageColor());
  }

  @Builder
  private generalSettingsContent() {
    Scroll() {
      Column({ space: 0 }) {
        Text('常规')
          .width('100%')
          .fontSize(16)
          .fontColor(this.secondaryTextColor())
          .padding({ left: 16, top: 12, bottom: 8 });
        Row() {
          Column({ space: 4 }) {
            Text('点击复制')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('点击时将验证码复制到剪贴板')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Toggle({ type: ToggleType.Switch, isOn: this.tapToCopy })
            .selectedColor(this.primaryColor())
            .onChange((value: boolean) => this.saveAppPreferences(this.viewMode, this.sortMode,
              this.codeGroupSize, this.showUsernames, value));
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 });
        Row() {
          Column({ space: 4 }) {
            Text('显示用户名')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('在验证器卡片上显示账号名称')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Toggle({ type: ToggleType.Switch, isOn: this.showUsernames })
            .selectedColor(this.primaryColor())
            .onChange((value: boolean) => this.saveAppPreferences(this.viewMode, this.sortMode,
              this.codeGroupSize, value, this.tapToCopy));
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 });
        Text('安全')
          .width('100%')
          .fontSize(16)
          .fontColor(this.secondaryTextColor())
          .padding({ left: 16, top: 12, bottom: 8 });
        Row() {
          Column({ space: 4 }) {
            Text('深色主题')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('使用深色界面')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Toggle({ type: ToggleType.Switch, isOn: this.darkMode })
            .selectedColor(this.primaryColor())
            .onChange(() => this.toggleTheme());
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 });
        Text('外观')
          .width('100%')
          .fontSize(16)
          .fontColor(this.secondaryTextColor())
          .padding({ left: 16, top: 12, bottom: 8 });
        Row() {
          Column({ space: 4 }) {
            Text('视图')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('选择验证器列表的视图')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Button(this.viewModeLabel())
            .fontSize(14)
            .backgroundColor('transparent')
            .fontColor(this.primaryColor())
            .onClick(() => {
              const next: AuthenticatorViewMode = this.viewMode === 'default' ? 'compact' :
                this.viewMode === 'compact' ? 'tile' : 'default';
              this.saveAppPreferences(next);
            });
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 });
        Row() {
          Column({ space: 4 }) {
            Text('验证码分组')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('设置验证码数字的分组方式')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Button(this.codeGroupLabel())
            .fontSize(14)
            .backgroundColor('transparent')
            .fontColor(this.primaryColor())
            .onClick(() => this.saveAppPreferences(this.viewMode, this.sortMode, this.nextCodeGroupSize()));
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 });
        Row() {
          Column({ space: 4 }) {
            Text('备份与恢复')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('导入或导出 FUN 加密备份')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Button('›')
            .fontSize(24)
            .backgroundColor('transparent')
            .fontColor(this.secondaryTextColor())
            .onClick(() => this.settingsPage = 'backup');
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 });
        Row() {
          Column({ space: 4 }) {
            Text('分类')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('管理验证器分类')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Button('›')
            .fontSize(24)
            .backgroundColor('transparent')
            .fontColor(this.secondaryTextColor())
            .onClick(() => this.settingsPage = 'categories');
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 });
        Text('关于')
          .width('100%')
          .fontSize(16)
          .fontColor(this.secondaryTextColor())
          .padding({ left: 16, top: 12, bottom: 8 });
        Row() {
          Column({ space: 4 }) {
            Text('隐私协议')
              .fontSize(16)
              .fontColor(this.primaryTextColor());
            Text('查看应用隐私政策')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
          .alignItems(HorizontalAlign.Start)
          .layoutWeight(1);
          Text('›')
            .fontSize(24)
            .fontColor(this.secondaryTextColor());
        }
        .width('100%')
        .padding({ left: 20, right: 20, top: 16, bottom: 16 })
        .onClick(() => this.openPrivacyPolicy());
        Text('验证码仅保存在本机应用沙箱中，无需网络生成。')
          .fontSize(12)
          .fontColor(this.secondaryTextColor())
          .padding({ left: 20, right: 20, top: 12, bottom: 20 });
        if (this.statusMessage.length > 0) {
          Text(this.statusMessage)
            .fontSize(13)
            .fontColor(this.darkMode ? '#FFB4AB' : '#BA1A1A')
            .padding({ left: 20, right: 20, bottom: 16 });
        }
      }
    }
    .layoutWeight(1)
    .scrollBar(BarState.Auto);
  }

  @Builder
  private categoriesSettingsContent() {
    Scroll() {
      Column({ space: 12 }) {
        Text('管理验证器分类')
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Row({ space: 8 }) {
          TextInput({ placeholder: '分类名称', text: this.categoryName })
            .layoutWeight(1)
            .fontSize(16)
            .backgroundColor('transparent')
            .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
            .padding({ left: 16, right: 16, top: 10, bottom: 10 })
            .onChange((value: string) => this.categoryName = value);
          Button('+')
            .width(48)
            .height(48)
            .fontSize(24)
            .backgroundColor(this.accentSoftColor())
            .fontColor(this.onAccentSoftColor())
            .borderRadius(8)
            .onClick(() => this.createCategory());
        }
        ForEach(this.vault.categories, (category: AuthenticatorCategory) => {
          Row() {
            Text(category.name)
              .fontSize(16)
              .fontColor(this.primaryTextColor())
              .layoutWeight(1);
            Button() {
              Text('×')
                .fontSize(24)
                .fontColor(this.secondaryTextColor());
            }
              .width(48)
              .height(48)
              .padding(0)
              .backgroundColor('transparent')
              .onClick(() => this.removeCategory(category.id));
          }
          .width('100%')
          .padding({ left: 16, right: 8, top: 8, bottom: 8 })
          .backgroundColor(this.surfaceColor())
          .borderRadius(8);
        }, (category: AuthenticatorCategory) => category.id);
        if (this.vault.categories.length === 0) {
          Text('尚未创建分类。')
            .fontSize(14)
            .fontColor(this.secondaryTextColor());
        }
        if (this.statusMessage.length > 0) {
          Text(this.statusMessage)
            .fontSize(13)
            .fontColor(this.darkMode ? '#FFB4AB' : '#BA1A1A');
        }
      }
      .width('100%')
      .justifyContent(FlexAlign.Start)
      .alignItems(HorizontalAlign.Start)
      .padding({ left: 20, right: 20, top: 16, bottom: 20 });
    }
    .layoutWeight(1)
    .scrollBar(BarState.Auto)
    .scrollable(ScrollDirection.Vertical)
    .initialOffset({ xOffset: 0, yOffset: 0 })
    .align(Alignment.TopStart);
  }

  @Builder
  private backupSettingsContent() {
    Scroll() {
      Column({ space: 14 }) {
        Text('FUN 备份采用 Argon2id 与 AES-GCM 加密；恢复时合并账号，不会覆盖其他记录。')
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Button('恢复 FUN 备份')
          .width('100%')
          .height(48)
          .backgroundColor('transparent')
          .fontColor(this.primaryColor())
          .border({ width: 1, color: this.primaryColor(), radius: 8 })
          .onClick(() => this.chooseBackupFile());
        Button('导入 Stratum 文件')
          .width('100%')
          .height(48)
          .backgroundColor('transparent')
          .fontColor(this.primaryColor())
          .border({ width: 1, color: this.primaryColor(), radius: 8 })
          .onClick(() => this.chooseStratumFile());
        Button('导出 FUN 加密备份')
          .width('100%')
          .height(48)
          .backgroundColor(this.primaryColor())
          .fontColor('#FFFFFF')
          .borderRadius(8)
          .onClick(() => this.openExportPasswordDialog());
        if (this.statusMessage.length > 0) {
          Text(this.statusMessage)
            .fontSize(13)
            .fontColor(this.statusMessage.includes('失败') || this.statusMessage.includes('错误')
              ? (this.darkMode ? '#FFB4AB' : '#BA1A1A') : this.primaryTextColor());
        }
      }
      .padding({ left: 20, right: 20, top: 16, bottom: 20 });
    }
    .layoutWeight(1)
    .scrollBar(BarState.Auto);
  }

  @Builder
  private iconPacksContent() {
    Scroll() {
      Column({ space: 12 }) {
        Text('导入 Stratum 图标包后，可以在账号的“更改图标”中使用其中的图标。删除图标包不会删除已应用到账号的图标。')
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Button('导入图标包')
          .width('100%')
          .height(48)
          .backgroundColor(this.primaryColor())
          .fontColor('#FFFFFF')
          .borderRadius(8)
          .onClick(() => this.importIconPack());
        Button('浏览可下载的图标包')
          .width('100%')
          .height(48)
          .backgroundColor('transparent')
          .fontColor(this.primaryColor())
          .border({ width: 1, color: this.primaryColor(), radius: 24 })
          .onClick(() => this.openIconPackWebsite());
        if (this.iconPacks.length === 0) {
          Text('尚未导入图标包。')
            .width('100%')
            .fontSize(14)
            .fontColor(this.secondaryTextColor())
            .textAlign(TextAlign.Center)
            .padding({ top: 24, bottom: 24 });
        }
        ForEach(this.iconPacks, (pack: IconPack) => {
          Column({ space: 8 }) {
            Row() {
              Text(pack.name)
                .fontSize(17)
                .fontWeight(FontWeight.Medium)
                .fontColor(this.primaryTextColor())
                .layoutWeight(1);
              Text(`${pack.icons.length} 个图标`)
                .fontSize(13)
                .fontColor(this.secondaryTextColor());
            }
            if (pack.description.length > 0) {
              Text(pack.description)
                .width('100%')
                .fontSize(13)
                .fontColor(this.secondaryTextColor());
            }
            Row({ space: 8 }) {
              if (pack.url.length > 0) {
                Button('查看来源')
                  .layoutWeight(1)
                  .backgroundColor('transparent')
                  .fontColor(this.primaryColor())
                  .onClick(() => this.openIconPackWebsite(pack.url));
              }
              Button('删除')
                .layoutWeight(1)
                .backgroundColor('transparent')
                .fontColor(this.darkMode ? '#FFB4AB' : '#BA1A1A')
                .onClick(() => this.requestIconPackDelete(pack.name));
            }
          }
          .width('100%')
          .padding(16)
          .backgroundColor(this.surfaceColor())
          .borderRadius(8);
        }, (pack: IconPack) => pack.name);
        if (this.statusMessage.length > 0) {
          Text(this.statusMessage)
            .fontSize(13)
            .fontColor(this.darkMode ? '#FFB4AB' : '#BA1A1A');
        }
      }
      .padding({ left: 20, right: 20, top: 16, bottom: 20 });
    }
    .layoutWeight(1)
    .scrollBar(BarState.Auto);
  }

  @Builder
  private qrCodeDialog() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.closeQrCode());
      Column({ space: 14 }) {
        Text('账号二维码')
          .width('100%')
          .fontSize(22)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center);
        QRCode(this.qrUri)
          .width(260)
          .height(260)
          .padding(12)
          .backgroundColor('#FFFFFF');
        Text('二维码包含账号密钥，请勿分享给他人。')
          .width('100%')
          .fontSize(13)
          .fontColor(this.secondaryTextColor())
          .textAlign(TextAlign.Center);
        if (this.statusMessage.length > 0) {
          Text(this.statusMessage)
            .fontSize(13)
            .fontColor(this.darkMode ? '#FFB4AB' : '#BA1A1A');
        }
        Row({ space: 8 }) {
          Button('关闭')
            .layoutWeight(1)
            .backgroundColor(this.surfaceColor())
            .fontColor(this.primaryTextColor())
            .onClick(() => this.closeQrCode());
          Button('复制 URI')
            .layoutWeight(1)
            .backgroundColor(this.primaryColor())
            .fontColor('#FFFFFF')
            .onClick(() => this.showQrCopyWarning = true);
        }
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 20, bottom: 20 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private qrCopyWarningDialog() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showQrCopyWarning = false);
      Column({ space: 12 }) {
        Text('复制账号 URI？')
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.primaryTextColor());
        Text('URI 中包含账号密钥。仅在可信设备或应用间使用。')
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Row({ space: 8 }) {
          Button('取消')
            .layoutWeight(1)
            .backgroundColor(this.surfaceColor())
            .fontColor(this.primaryTextColor())
            .onClick(() => this.showQrCopyWarning = false);
          Button('复制')
            .layoutWeight(1)
            .backgroundColor(this.primaryColor())
            .fontColor('#FFFFFF')
            .onClick(() => this.copyQrUri());
        }
      }
      .width('100%')
      .padding(22)
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 12, topRight: 12 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#99000000');
  }

  @Builder
  private iconPickerSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => {
        this.showIconPicker = false;
        this.iconPickerAuthenticatorId = '';
      });
      Column({ space: 10 }) {
        Row() {
          Text('选择图标')
            .fontSize(22)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.primaryTextColor())
            .layoutWeight(1);
          Button('×')
            .width(40)
            .height(40)
            .padding(0)
            .backgroundColor('transparent')
            .fontColor(this.secondaryTextColor())
            .onClick(() => {
              this.showIconPicker = false;
              this.iconPickerAuthenticatorId = '';
            });
        }
        TextInput({ placeholder: '搜索图标', text: this.iconSearchText })
          .height(48)
          .backgroundColor(this.surfaceColor())
          .onChange((value: string) => this.iconSearchText = value);
        Scroll() {
          Row({ space: 8 }) {
            Button('默认')
              .fontSize(14)
              .backgroundColor(this.selectedIconPackName.length === 0
                ? this.accentSoftColor() : this.surfaceColor())
              .fontColor(this.selectedIconPackName.length === 0
                ? this.onAccentSoftColor() : this.primaryTextColor())
              .onClick(() => this.selectedIconPackName = '');
            ForEach(this.iconPacks, (pack: IconPack) => {
              Button(pack.name)
                .fontSize(14)
                .backgroundColor(this.selectedIconPackName === pack.name
                  ? this.accentSoftColor() : this.surfaceColor())
                .fontColor(this.selectedIconPackName === pack.name
                  ? this.onAccentSoftColor() : this.primaryTextColor())
                .onClick(() => this.selectedIconPackName = pack.name);
            }, (pack: IconPack) => pack.name);
          }
        }
        .scrollable(ScrollDirection.Horizontal)
        .scrollBar(BarState.Off);
        Row({ space: 8 }) {
          Button('恢复默认图标')
            .layoutWeight(1)
            .backgroundColor(this.surfaceColor())
            .fontColor(this.primaryTextColor())
            .onClick(() => this.resetAccountIcon());
          Button('从图片选择')
            .layoutWeight(1)
            .backgroundColor(this.surfaceColor())
            .fontColor(this.primaryTextColor())
            .onClick(() => this.importCustomIconForAccount());
        }
        if (this.selectedIconPackName.length === 0) {
          if (this.filteredDefaultIconKeys().length === 0) {
            Text('没有匹配的图标。')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
          }
        } else if (this.selectedIconEntries().length === 0) {
          Text('没有匹配的图标。')
            .fontSize(14)
            .fontColor(this.secondaryTextColor());
        }
        if (this.statusMessage.length > 0) {
          Text(this.statusMessage)
            .fontSize(13)
            .fontColor(this.darkMode ? '#FFB4AB' : '#BA1A1A');
        }
        Scroll() {
          Grid() {
            if (this.selectedIconPackName.length === 0) {
              ForEach(this.filteredDefaultIconKeys(), (iconKey: string) => {
                GridItem() {
                  Column({ space: 6 }) {
                    Image(this.defaultIconSource(iconKey))
                      .width(48)
                      .height(48);
                    Text(iconKey)
                      .width('100%')
                      .fontSize(11)
                      .fontColor(this.primaryTextColor())
                      .maxLines(1)
                      .textOverflow({ overflow: TextOverflow.Ellipsis })
                      .textAlign(TextAlign.Center);
                  }
                  .width('100%')
                  .height(82)
                  .justifyContent(FlexAlign.Center)
                  .onClick(() => this.assignDefaultIcon(iconKey));
                }
              }, (iconKey: string) => iconKey);
            } else {
              ForEach(this.selectedIconEntries(), (icon: IconPackEntry) => {
                GridItem() {
                  Column({ space: 6 }) {
                    Image(this.iconImageSource(icon.data))
                      .width(48)
                      .height(48);
                    Text(icon.name)
                      .width('100%')
                      .fontSize(11)
                      .fontColor(this.primaryTextColor())
                      .maxLines(1)
                      .textOverflow({ overflow: TextOverflow.Ellipsis })
                      .textAlign(TextAlign.Center);
                  }
                  .width('100%')
                  .height(82)
                  .justifyContent(FlexAlign.Center)
                  .onClick(() => this.assignCustomIcon(icon.data));
                }
              }, (icon: IconPackEntry) => icon.name);
            }
          }
          .columnsTemplate('1fr 1fr 1fr 1fr')
          .columnsGap(8)
          .rowsGap(8)
          .width('100%');
        }
        .layoutWeight(1)
        .scrollBar(BarState.Auto);
      }
      .width('100%')
      .height('76%')
      .padding({ left: 20, right: 20, bottom: 16 })
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private iconPackDeleteDialog() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showIconPackDeleteDialog = false);
      Column({ space: 12 }) {
        Text('删除图标包？')
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.primaryTextColor());
        Text('已应用到账号的图标会保留。')
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Row({ space: 8 }) {
          Button('取消')
            .layoutWeight(1)
            .backgroundColor(this.darkMode ? '#374151' : '#EDF1F8')
            .fontColor(this.primaryTextColor())
            .onClick(() => this.showIconPackDeleteDialog = false);
          Button('删除')
            .layoutWeight(1)
            .backgroundColor('#B42318')
            .fontColor('#FFFFFF')
            .onClick(() => this.confirmIconPackDelete());
        }
      }
      .width('100%')
      .padding(22)
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 12, topRight: 12 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#99000000');
  }

  @Builder
  private guideSheet() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showGuide = false);
      Column() {
        this.sheetHandle();
        Text('入门指南')
          .width('100%')
          .fontSize(22)
          .fontWeight(FontWeight.Medium)
          .fontColor(this.primaryTextColor())
          .textAlign(TextAlign.Center)
          .margin({ bottom: 12 });
        Scroll() {
          Column({ space: 16 }) {
            Row({ space: 12 }) {
              Image($rawfile('add-account.svg'))
                .width(28)
                .height(28)
                .fillColor(this.primaryTextColor())
                .supportSvg2(true);
              Column({ space: 4 }) {
                Text('1. 选择添加方式')
                  .fontSize(16)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(this.primaryTextColor());
                Text('点击底部“+”，可扫描二维码、手动输入密钥或粘贴 otpauth:// URI。')
                  .fontSize(14)
                  .fontColor(this.secondaryTextColor());
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1);
            }
            .width('100%')
            .alignItems(VerticalAlign.Top);
            Row({ space: 12 }) {
              Image($rawfile('apps.svg'))
                .width(28)
                .height(28)
                .fillColor(this.primaryTextColor())
                .supportSvg2(true);
              Column({ space: 4 }) {
                Text('2. 导入已有账号')
                  .fontSize(16)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(this.primaryTextColor());
                Text('从“从其他应用导入”选择 Stratum 备份文件或 URI list 文本；也可选择恢复 FUN 加密备份。备份恢复会合并账号。')
                  .fontSize(14)
                  .fontColor(this.secondaryTextColor());
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1);
            }
            .width('100%')
            .alignItems(VerticalAlign.Top);
            Row({ space: 12 }) {
              Image($rawfile('check.svg'))
                .width(28)
                .height(28)
                .fillColor(this.primaryTextColor())
                .supportSvg2(true);
              Column({ space: 4 }) {
                Text('3. 检查并保存')
                  .fontSize(16)
                  .fontWeight(FontWeight.Medium)
                  .fontColor(this.primaryTextColor());
                Text('确认发行方、用户名和密钥正确后点击“添加”。如需整理账号，可在账号菜单的“指定分类”中新建分类并直接分配。')
                  .fontSize(14)
                  .fontColor(this.secondaryTextColor());
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1);
            }
            .width('100%')
            .alignItems(VerticalAlign.Top);
            Text('验证码在本机生成。请妥善保管密钥和备份密码。')
              .width('100%')
              .fontSize(13)
              .fontColor(this.secondaryTextColor());
          }
          .width('100%')
          .padding({ left: 20, right: 20, bottom: 16 });
        }
        .layoutWeight(1)
        .width('100%')
        .scrollBar(BarState.Auto);
        Button('开始添加')
          .width('100%')
          .height(48)
          .backgroundColor(this.primaryColor())
          .fontColor('#FFFFFF')
          .borderRadius(8)
          .margin({ bottom: 20 })
          .onClick(() => {
            this.showGuide = false;
            this.showAddMenu = true;
          });
      }
      .width('100%')
      .height('70%')
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 16, topRight: 16 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#66000000');
  }

  @Builder
  private editorContent() {
    Column() {
      this.sheetHandle();
      Text(this.editingId.length === 0 ? '输入提供的密钥' : '编辑')
        .width('100%')
        .fontSize(24)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.primaryTextColor())
        .textAlign(TextAlign.Center)
        .margin({ bottom: 18 });
      Scroll() {
        Column({ space: 12 }) {
          Button(this.typeLabel(this.editor.type))
            .width('100%')
            .height(56)
            .fontSize(16)
            .backgroundColor('transparent')
            .fontColor(this.primaryTextColor())
            .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
            .onClick(() => this.showTypeOptions = !this.showTypeOptions);
          if (this.showTypeOptions) {
            Scroll() {
              Row({ space: 8 }) {
                ForEach(TYPES, (type: AuthenticatorType) => {
                  Button(this.typeLabel(type))
                    .fontSize(13)
                    .backgroundColor(this.editor.type === type ? this.accentSoftColor() : this.surfaceColor())
                    .fontColor(this.editor.type === type ? this.onAccentSoftColor() : this.primaryTextColor())
                    .onClick(() => {
                      const digits = type === this.editor.type ? this.editor.digits :
                        type === 'TOTP' || type === 'HOTP' ? 6 : type === 'Steam' ? 5 : type === 'Yandex' ? 8 : 6;
                      this.setEditor({ type, digits });
                      this.digitsText = String(digits);
                      this.showTypeOptions = false;
                    });
                }, (type: AuthenticatorType) => type);
              }
            }
            .scrollable(ScrollDirection.Horizontal)
            .scrollBar(BarState.Off);
          }
          TextInput({ placeholder: '发行方（如：Google）', text: this.editor.issuer })
            .height(56)
            .fontSize(16)
            .fontColor(this.primaryTextColor())
            .backgroundColor('transparent')
            .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
            .padding({ left: 16, right: 16 })
            .onChange((value: string) => this.setEditor({ issuer: value }));
          TextInput({ placeholder: '用户名（选填）', text: this.editor.username })
            .height(56)
            .fontSize(16)
            .fontColor(this.primaryTextColor())
            .backgroundColor('transparent')
            .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
            .padding({ left: 16, right: 16 })
            .onChange((value: string) => this.setEditor({ username: value }));
          TextInput({ placeholder: '密钥', text: this.editor.secret })
            .height(56)
            .fontSize(16)
            .fontColor(this.primaryTextColor())
            .backgroundColor('transparent')
            .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
            .padding({ left: 16, right: 16 })
            .onChange((value: string) => this.setEditor({ secret: value }));
          if (this.editor.type === 'mOTP' || this.editor.type === 'Yandex') {
            TextInput({ placeholder: this.editor.type === 'mOTP' ? 'PIN' : 'Yandex PIN', text: this.editor.pin })
              .height(56)
              .fontSize(16)
              .fontColor(this.primaryTextColor())
              .backgroundColor('transparent')
              .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
              .padding({ left: 16, right: 16 })
              .onChange((value: string) => this.setEditor({ pin: value }));
          }
          Button(this.showAdvancedOptions ? '隐藏高级选项' : '显示高级选项')
            .width('100%')
            .height(48)
            .fontSize(15)
            .backgroundColor('transparent')
            .fontColor(this.primaryColor())
            .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 24 })
            .onClick(() => this.showAdvancedOptions = !this.showAdvancedOptions);
          if (this.showAdvancedOptions) {
            TextInput({ placeholder: '图标标识（选填）', text: this.editor.icon })
              .height(56)
              .fontSize(16)
              .backgroundColor('transparent')
              .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
              .padding({ left: 16, right: 16 })
              .onChange((value: string) => this.setEditor({ icon: value }));
            if (this.editor.type === 'TOTP' || this.editor.type === 'HOTP') {
              Text('算法')
                .fontSize(14)
                .fontColor(this.secondaryTextColor());
              Row({ space: 8 }) {
                ForEach(ALGORITHMS, (algorithm: OtpAlgorithm) => {
                  Button(algorithm)
                    .fontSize(13)
                    .backgroundColor(this.editor.algorithm === algorithm ? this.accentSoftColor() : this.surfaceColor())
                    .fontColor(this.editor.algorithm === algorithm ? this.onAccentSoftColor() : this.primaryTextColor())
                    .onClick(() => this.setEditor({ algorithm }));
                }, (algorithm: OtpAlgorithm) => algorithm);
              }
              Row({ space: 8 }) {
                TextInput({ placeholder: '位数', text: this.digitsText })
                  .layoutWeight(1)
                  .height(56)
                  .backgroundColor('transparent')
                  .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
                  .padding({ left: 16, right: 16 })
                  .onChange((value: string) => {
                    this.digitsText = value;
                    this.setEditor({ digits: Number(value) });
                  });
                if (this.editor.type === 'TOTP') {
                  TextInput({ placeholder: '时间间隔（秒）', text: this.periodText })
                    .layoutWeight(1)
                    .height(56)
                    .backgroundColor('transparent')
                    .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
                    .padding({ left: 16, right: 16 })
                    .onChange((value: string) => {
                      this.periodText = value;
                      this.setEditor({ period: Number(value) });
                    });
                }
              }
            }
            if (this.editor.type === 'HOTP') {
              TextInput({ placeholder: '计数器', text: this.counterText })
                .height(56)
                .backgroundColor('transparent')
                .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
                .padding({ left: 16, right: 16 })
                .onChange((value: string) => {
                  this.counterText = value;
                  this.setEditor({ counter: Number(value) });
                });
            }
            Text('分类')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
            Scroll() {
              Row({ space: 8 }) {
                Button('未分类')
                  .backgroundColor(this.editor.categoryId.length === 0 ? this.accentSoftColor() : this.surfaceColor())
                  .fontColor(this.editor.categoryId.length === 0 ? this.onAccentSoftColor() : this.primaryTextColor())
                  .onClick(() => this.setEditor({ categoryId: '' }));
                ForEach(this.vault.categories, (category: AuthenticatorCategory) => {
                  Button(category.name)
                    .backgroundColor(this.editor.categoryId === category.id ? this.accentSoftColor() : this.surfaceColor())
                    .fontColor(this.editor.categoryId === category.id ? this.onAccentSoftColor() : this.primaryTextColor())
                    .onClick(() => this.setEditor({ categoryId: category.id }));
                }, (category: AuthenticatorCategory) => category.id);
              }
            }
            .scrollable(ScrollDirection.Horizontal)
            .scrollBar(BarState.Off);
            Text('从二维码或文本 URI 导入')
              .fontSize(14)
              .fontColor(this.secondaryTextColor());
            TextInput({ placeholder: '粘贴 otpauth:// 或 motp:// URI', text: this.uriText })
              .height(56)
              .backgroundColor('transparent')
              .border({ width: 1, color: this.darkMode ? '#737A82' : '#71787E', radius: 4 })
              .padding({ left: 16, right: 16 })
              .onChange((value: string) => this.uriText = value);
            Row({ space: 8 }) {
              Button('解析 URI')
                .layoutWeight(1)
                .backgroundColor(this.surfaceColor())
                .fontColor(this.primaryTextColor())
                .onClick(() => this.parseOtpUriField());
              Button('扫描二维码')
                .layoutWeight(1)
                .backgroundColor(this.surfaceColor())
                .fontColor(this.primaryTextColor())
                .onClick(() => this.scanOtpUri());
            }
          }
          if (this.statusMessage.length > 0) {
            Text(this.statusMessage)
              .fontSize(13)
              .fontColor(this.darkMode ? '#FFB4AB' : '#BA1A1A');
          }
        }
        .width('100%')
        .constraintSize({ minHeight: '100%' })
        .alignItems(HorizontalAlign.Start)
        .justifyContent(FlexAlign.Start)
        .padding({ left: 16, right: 16, bottom: 20 });
      }
      .layoutWeight(1)
      .scrollBar(BarState.Auto);

      Row({ space: 12 }) {
        Blank();
        Button('取消')
          .fontSize(16)
          .backgroundColor('transparent')
          .fontColor(this.primaryColor())
          .onClick(() => this.showEditor = false);
        Button(this.editingId.length === 0 ? '添加' : '保存')
          .height(48)
          .fontSize(16)
          .backgroundColor(this.primaryColor())
          .fontColor('#FFFFFF')
          .borderRadius(8)
          .padding({ left: 28, right: 28 })
          .onClick(() => this.saveAuthenticator());
      }
      .width('100%')
      .padding({ left: 16, right: 16, top: 8, bottom: 16 });
    }
    .width('100%')
    .height('100%')
    .padding({ left: 16, right: 16 })
    .backgroundColor(this.pageColor())
    .borderRadius({ topLeft: 16, topRight: 16 });
  }

  @Builder
  private passwordDialog() {
    Column() {
      Blank().layoutWeight(1).onClick(() => {
        this.showPasswordDialog = false;
        this.password = '';
      });
      Column({ space: 12 }) {
        Text(this.backupAction === 'export' ? '导出 FUN 加密备份' :
          this.backupAction === 'externalImport' ? `导入${labelForFormat(this.pendingExternalImportFormat)}备份` :
            this.backupAction === 'stratumImport' ? '导入 Stratum 文件' : '恢复 FUN 备份')
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.primaryTextColor());
        Text(this.backupAction === 'export'
          ? '此格式仅供 FUN Authenticator 使用。密码仅用于本次加密，不会保存。'
          : this.backupAction === 'externalImport'
            ? '请输入来源应用备份密码。密码不会保存或写入日志。'
            : this.backupAction === 'stratumImport'
              ? '请输入 Stratum 备份密码；未加密的 JSON 备份可留空。密码不会保存。'
              : '请输入 FUN 备份密码。密码不会保存。')
          .fontSize(13)
          .fontColor(this.secondaryTextColor());
        TextInput({ placeholder: '备份密码', text: this.password })
          .type(InputType.Password)
          .onChange((value: string) => this.password = value);
        if (this.statusMessage.length > 0) {
          Text(this.statusMessage)
            .fontSize(13)
            .fontColor('#B42318');
        }
        Row({ space: 8 }) {
          Button('取消')
            .layoutWeight(1)
            .backgroundColor(this.darkMode ? '#374151' : '#EDF1F8')
            .fontColor(this.primaryTextColor())
            .onClick(() => {
              this.showPasswordDialog = false;
              this.password = '';
            });
          Button('继续')
            .layoutWeight(1)
            .backgroundColor('#325BEA')
            .fontColor('#FFFFFF')
            .onClick(() => this.confirmPassword());
        }
      }
      .width('100%')
      .padding(22)
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 12, topRight: 12 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#99000000');
  }

  @Builder
  private restoreDialog() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.cancelRestore());
      Column({ space: 12 }) {
        Text('确认恢复备份')
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.primaryTextColor());
        Text(`此操作会将备份合并到当前 ${this.vault.authenticators.length} 个账号中；相同密钥会更新。备份包含 ${this.pendingRestoreVault.authenticators.length} 个账号。`)
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Row({ space: 8 }) {
          Button('取消')
            .layoutWeight(1)
            .backgroundColor(this.darkMode ? '#374151' : '#EDF1F8')
            .fontColor(this.primaryTextColor())
            .onClick(() => this.cancelRestore());
          Button('合并并导入')
            .layoutWeight(1)
            .backgroundColor(this.primaryColor())
            .fontColor('#FFFFFF')
            .onClick(() => this.acceptRestore());
        }
      }
      .width('100%')
      .padding(22)
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 12, topRight: 12 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#99000000');
  }

  @Builder
  private deleteDialog() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.showDeleteDialog = false);
      Column({ space: 12 }) {
        Text('删除账号？')
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.primaryTextColor());
        Text('此操作无法撤销。')
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Row({ space: 8 }) {
          Button('取消')
            .layoutWeight(1)
            .backgroundColor(this.darkMode ? '#374151' : '#EDF1F8')
            .fontColor(this.primaryTextColor())
            .onClick(() => this.showDeleteDialog = false);
          Button('删除')
            .layoutWeight(1)
            .backgroundColor('#B42318')
            .fontColor('#FFFFFF')
            .onClick(() => this.confirmDelete());
        }
      }
      .width('100%')
      .padding(22)
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 12, topRight: 12 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#99000000');
  }

  @Builder
  private migrationDialog() {
    Column() {
      Blank().layoutWeight(1).onClick(() => this.cancelMigration());
      Column({ space: 12 }) {
        Text('导入 Google Authenticator 账号')
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .fontColor(this.primaryTextColor());
        Text(`二维码包含 ${this.pendingMigrationAccounts.length} 个账号；其中 ${this.newMigrationAccountCount()} 个是新账号。重复密钥将跳过。`)
          .fontSize(14)
          .fontColor(this.secondaryTextColor());
        Row({ space: 8 }) {
          Button('取消')
            .layoutWeight(1)
            .backgroundColor(this.darkMode ? '#374151' : '#EDF1F8')
            .fontColor(this.primaryTextColor())
            .onClick(() => this.cancelMigration());
          Button('添加新账号')
            .layoutWeight(1)
            .backgroundColor('#325BEA')
            .fontColor('#FFFFFF')
            .onClick(() => this.acceptMigration());
        }
      }
      .width('100%')
      .padding(22)
      .backgroundColor(this.pageColor())
      .borderRadius({ topLeft: 12, topRight: 12 });
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#99000000');
  }

  build() {
    Stack() {
      Column() {
        if (this.showSettings) {
          this.settingsContent();
        } else {
          this.header();
          this.homeContent();
          this.bottomBar();
        }
      }
      .width('100%')
      .height('100%')
      .backgroundColor(this.pageColor());

      if (this.showCategoryMenu) {
        this.categoryMenuSheet();
      }
      if (this.showMainMenu) {
        this.mainMenuSheet();
      }
      if (this.showAddMenu) {
        this.addMenuSheet();
      }
      if (this.showImportMenu) {
        this.importMenuSheet();
      }
      if (this.showGuide) {
        this.guideSheet();
      }
      if (this.showSortMenu) {
        this.sortMenu();
      }
      if (this.accountMenuId.length > 0) {
        this.accountMenuSheet();
      }
      if (this.reorderId.length > 0) {
        this.reorderSheet();
      }
      if (this.categoryAssignmentId.length > 0) {
        this.categoryAssignmentSheet();
      }
      if (this.showEditor) {
        Column() {
          Blank().layoutWeight(1).onClick(() => this.showEditor = false);
          this.editorContent();
        }
        .width('100%')
        .height('100%')
        .backgroundColor('#99000000');
      }
      if (this.showPasswordDialog) {
        this.passwordDialog();
      }
      if (this.showRestoreDialog) {
        this.restoreDialog();
      }
      if (this.showDeleteDialog) {
        this.deleteDialog();
      }
      if (this.showMigrationDialog) {
        this.migrationDialog();
      }
      if (this.showIconPicker) {
        this.iconPickerSheet();
      }
      if (this.showIconPackDeleteDialog) {
        this.iconPackDeleteDialog();
      }
      if (this.showQrCodeDialog) {
        this.qrCodeDialog();
      }
      if (this.showQrCopyWarning) {
        this.qrCopyWarningDialog();
      }
      if (this.isBackupBusy || this.isIconPackBusy) {
        Column({ space: 12 }) {
          LoadingProgress()
            .width(40)
            .height(40)
            .color(this.primaryColor());
          Text(this.busyMessage)
            .fontSize(14)
            .fontColor(this.primaryTextColor());
        }
        .width('100%')
        .height('100%')
        .justifyContent(FlexAlign.Center)
        .alignItems(HorizontalAlign.Center)
        .backgroundColor('#66000000')
        .onClick(() => {});
      }
    }
    .width('100%')
    .height('100%');
  }
}
