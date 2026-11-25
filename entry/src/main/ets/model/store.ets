import { common } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { AuthenticatorCategory, AuthenticatorRecord, CustomIcon, emptyVault, validateAuthenticator, VaultData } from './otp';
import { IconPack, IconPackEntry } from './iconpack';

const PREFERENCES_NAME = 'authenticator_vault';
const VAULT_KEY = 'vault';
const APP_PREFERENCES_KEY = 'appPreferences';
const ICON_PACKS_KEY = 'iconPacks';

export type AuthenticatorViewMode = 'default' | 'compact' | 'tile';
export type AuthenticatorSortMode = 'az' | 'za' | 'mostCopied' | 'leastCopied' | 'custom';

export interface AppPreferences {
  viewMode: AuthenticatorViewMode;
  sortMode: AuthenticatorSortMode;
  codeGroupSize: number;
  showUsernames: boolean;
  tapToCopy: boolean;
  lockOrdering: boolean;
}

const DEFAULT_APP_PREFERENCES: AppPreferences = {
  viewMode: 'default',
  sortMode: 'az',
  codeGroupSize: 3,
  showUsernames: true,
  tapToCopy: true,
  lockOrdering: false
};

export class VaultStore {
  private readonly preferencesStore: preferences.Preferences;

  private constructor(preferencesStore: preferences.Preferences) {
    this.preferencesStore = preferencesStore;
  }

  static async open(context: common.UIAbilityContext): Promise<VaultStore> {
    const preferencesStore = await preferences.getPreferences(context, PREFERENCES_NAME);
    return new VaultStore(preferencesStore);
  }

  async load(): Promise<VaultData> {
    const storedValue = await this.preferencesStore.get(VAULT_KEY, '');
    if (typeof storedValue !== 'string') {
      throw new Error('Stored authenticator data has an invalid format.');
    }
    if (storedValue.length === 0) {
      return emptyVault();
    }

    const saved = JSON.parse(storedValue) as VaultData;
    if (!Array.isArray(saved.authenticators) || !Array.isArray(saved.categories) ||
      !Array.isArray(saved.customIcons)) {
      throw new Error('Stored authenticator data is invalid.');
    }
    return this.validateVault(saved);
  }

  async save(vault: VaultData): Promise<VaultData> {
    const validated = this.validateVault(vault);
    await this.preferencesStore.put(VAULT_KEY, JSON.stringify(validated));
    await this.preferencesStore.flush();
    return validated;
  }

  async loadDarkMode(): Promise<boolean> {
    const value = await this.preferencesStore.get('darkMode', false);
    if (typeof value !== 'boolean') {
      throw new Error('Stored appearance setting has an invalid format.');
    }
    return value;
  }

  async saveDarkMode(enabled: boolean): Promise<void> {
    await this.preferencesStore.put('darkMode', enabled);
    await this.preferencesStore.flush();
  }

  async loadAppPreferences(): Promise<AppPreferences> {
    const storedValue = await this.preferencesStore.get(APP_PREFERENCES_KEY, '');
    if (typeof storedValue !== 'string') {
      throw new Error('Stored application preferences have an invalid format.');
    }
    if (storedValue.length === 0) {
      return {
        viewMode: DEFAULT_APP_PREFERENCES.viewMode,
        sortMode: DEFAULT_APP_PREFERENCES.sortMode,
        codeGroupSize: DEFAULT_APP_PREFERENCES.codeGroupSize,
        showUsernames: DEFAULT_APP_PREFERENCES.showUsernames,
        tapToCopy: DEFAULT_APP_PREFERENCES.tapToCopy,
        lockOrdering: DEFAULT_APP_PREFERENCES.lockOrdering
      };
    }

    const parsed: Object = JSON.parse(storedValue);
    if (typeof parsed !== 'object' || parsed === null) {
      throw new Error('Stored application preferences are invalid.');
    }
    const value = parsed as Record<string, string | number | boolean>;
    const viewMode = value['viewMode'];
    const sortMode = value['sortMode'];
    const codeGroupSize = value['codeGroupSize'];
    const showUsernames = value['showUsernames'];
    const tapToCopy = value['tapToCopy'];
    const lockOrdering = value['lockOrdering'];
    if ((viewMode !== 'default' && viewMode !== 'compact' && viewMode !== 'tile') ||
      (sortMode !== 'az' && sortMode !== 'za' && sortMode !== 'mostCopied' &&
        sortMode !== 'leastCopied' && sortMode !== 'custom') ||
      (codeGroupSize !== 0 && codeGroupSize !== 2 && codeGroupSize !== 3 && codeGroupSize !== 4 &&
        codeGroupSize !== -2 && codeGroupSize !== -3) ||
      typeof showUsernames !== 'boolean' || typeof tapToCopy !== 'boolean' ||
      typeof lockOrdering !== 'boolean') {
      throw new Error('Stored application preferences are invalid.');
    }
    return { viewMode, sortMode, codeGroupSize, showUsernames, tapToCopy, lockOrdering };
  }

  async saveAppPreferences(value: AppPreferences): Promise<void> {
    if ((value.viewMode !== 'default' && value.viewMode !== 'compact' && value.viewMode !== 'tile') ||
      (value.sortMode !== 'az' && value.sortMode !== 'za' && value.sortMode !== 'mostCopied' &&
        value.sortMode !== 'leastCopied' && value.sortMode !== 'custom') ||
      (value.codeGroupSize !== 0 && value.codeGroupSize !== 2 && value.codeGroupSize !== 3 &&
        value.codeGroupSize !== 4 && value.codeGroupSize !== -2 && value.codeGroupSize !== -3) ||
      typeof value.showUsernames !== 'boolean' || typeof value.tapToCopy !== 'boolean' ||
      typeof value.lockOrdering !== 'boolean') {
      throw new Error('Application preferences contain an unsupported value.');
    }
    await this.preferencesStore.put(APP_PREFERENCES_KEY, JSON.stringify(value));
    await this.preferencesStore.flush();
  }

  async loadIconPacks(): Promise<Array<IconPack>> {
    const storedValue = await this.preferencesStore.get(ICON_PACKS_KEY, '');
    if (typeof storedValue !== 'string') {
      throw new Error('Stored icon-pack data has an invalid format.');
    }
    if (storedValue.length === 0) {
      return [];
    }
    const parsed: Object = JSON.parse(storedValue);
    if (!Array.isArray(parsed)) {
      throw new Error('Stored icon-pack data is invalid.');
    }
    return this.validateIconPacks(parsed as Array<IconPack>);
  }

  async saveIconPacks(iconPacks: Array<IconPack>): Promise<void> {
    const validated = this.validateIconPacks(iconPacks);
    await this.preferencesStore.put(ICON_PACKS_KEY, JSON.stringify(validated));
    await this.preferencesStore.flush();
  }

  private validateVault(vault: VaultData): VaultData {
    const authenticators = vault.authenticators.map((item: AuthenticatorRecord) => validateAuthenticator(item));
    const categories: Array<AuthenticatorCategory> = [];
    for (const item of vault.categories) {
      const category: AuthenticatorCategory = {
        id: item.id.trim(),
        name: item.name.trim(),
        ranking: item.ranking
      };
      categories.push(category);
    }
    const categoryIds = new Set<string>();
    const categoryNames = new Set<string>();
    for (const category of categories) {
      const normalisedName = category.name.toLocaleLowerCase();
      if (category.id.length === 0 || category.name.length === 0 ||
        categoryIds.has(category.id) || categoryNames.has(normalisedName)) {
        throw new Error('Categories must have unique non-empty names and IDs.');
      }
      categoryIds.add(category.id);
      categoryNames.add(normalisedName);
    }

    const secrets = new Set<string>();
    for (const item of authenticators) {
      if (secrets.has(item.secret)) {
        throw new Error('Authenticator secrets must be unique.');
      }
      if (item.categoryId.length > 0 && !categoryIds.has(item.categoryId)) {
        throw new Error('An authenticator refers to a category that no longer exists.');
      }
      secrets.add(item.secret);
    }

    const customIcons: Array<CustomIcon> = [];
    for (const item of vault.customIcons) {
      const icon: CustomIcon = { id: item.id, data: item.data };
      customIcons.push(icon);
    }
    const result: VaultData = {
      authenticators,
      categories,
      customIcons
    };
    return result;
  }

  private validateIconPacks(iconPacks: Array<IconPack>): Array<IconPack> {
    const names = new Set<string>();
    const validated: Array<IconPack> = [];
    for (const item of iconPacks) {
      if (item === undefined || item === null || typeof item.name !== 'string' ||
        typeof item.description !== 'string' || typeof item.url !== 'string' ||
        !Array.isArray(item.icons)) {
        throw new Error('Stored icon-pack data is invalid.');
      }
      const name = item.name.trim();
      const normalizedName = name.toLocaleLowerCase();
      if (name.length === 0 || item.icons.length === 0 || names.has(normalizedName)) {
        throw new Error('Icon packs must have unique non-empty names and icons.');
      }
      names.add(normalizedName);
      const iconNames = new Set<string>();
      const icons: Array<IconPackEntry> = [];
      for (const icon of item.icons) {
        if (icon === undefined || icon === null || typeof icon.name !== 'string' ||
          typeof icon.data !== 'string') {
          throw new Error('Stored icon-pack entries are invalid.');
        }
        const iconName = icon.name.trim();
        if (iconName.length === 0 || icon.data.length === 0 || iconNames.has(iconName)) {
          throw new Error('Icon packs contain an invalid or duplicate icon.');
        }
        iconNames.add(iconName);
        icons.push({ name: iconName, data: icon.data });
      }
      validated.push({
        name,
        description: item.description,
        url: item.url,
        icons
      });
    }
    return validated;
  }
}
