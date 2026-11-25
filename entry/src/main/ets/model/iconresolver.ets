import { DARK_ICON_KEYS, DEFAULT_ICON_KEYS } from './iconcatalog';

const DEFAULT_ICON_KEY_SET: Set<string> = new Set<string>(DEFAULT_ICON_KEYS);
const DARK_ICON_KEY_SET: Set<string> = new Set<string>(DARK_ICON_KEYS);

function normalizedIconKey(value: string): string {
  return value.toLocaleLowerCase().replace(/[^a-z0-9]/g, '');
}

export function iconKeyForIssuer(issuer: string): string {
  const key = normalizedIconKey(issuer);
  if (DEFAULT_ICON_KEY_SET.has(key)) {
    return key;
  }
  const firstWord = issuer.split(/[ .]/, 2)[0] ?? '';
  const firstWordKey = normalizedIconKey(firstWord);
  return DEFAULT_ICON_KEY_SET.has(firstWordKey) ? firstWordKey : '';
}

export function hasDarkIcon(iconKey: string): boolean {
  return DARK_ICON_KEY_SET.has(iconKey);
}

export function isDefaultIconKey(iconKey: string): boolean {
  return DEFAULT_ICON_KEY_SET.has(iconKey);
}
