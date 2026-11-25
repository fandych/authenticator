import util from '@ohos.util';

export interface IconPackEntry {
  name: string;
  data: string;
}

export interface IconPack {
  name: string;
  description: string;
  url: string;
  icons: Array<IconPackEntry>;
}

const MAX_ICON_PACK_SIZE = 32 * 1024 * 1024;
const BASE64 = new util.Base64Helper();
const TEXT_DECODER = new util.TextDecoder('utf-8');

interface ProtoCursor {
  offset: number;
}

export function parseStratumIconPack(data: Uint8Array): IconPack {
  if (data.length === 0 || data.length > MAX_ICON_PACK_SIZE) {
    throw new Error('The selected icon pack is empty or too large.');
  }

  const pack: IconPack = { name: '', description: '', url: '', icons: [] };
  const cursor: ProtoCursor = { offset: 0 };
  while (cursor.offset < data.length) {
    const key = readVarint(data, cursor);
    const fieldNumber = Math.floor(key / 8);
    const wireType = key & 7;
    if (fieldNumber === 0) {
      throw new Error('The selected file is not a valid Stratum icon pack.');
    }

    if (wireType === 2) {
      const value = readLengthDelimited(data, cursor);
      if (fieldNumber === 1) {
        pack.name = TEXT_DECODER.decodeToString(value);
      } else if (fieldNumber === 2) {
        pack.description = TEXT_DECODER.decodeToString(value);
      } else if (fieldNumber === 3) {
        pack.url = TEXT_DECODER.decodeToString(value);
      } else if (fieldNumber === 4) {
        pack.icons.push(parseIconPackEntry(value));
      }
    } else {
      skipField(data, cursor, wireType);
    }
  }

  pack.name = pack.name.trim();
  if (pack.name.length === 0 || pack.icons.length === 0) {
    throw new Error('The selected file is not a valid Stratum icon pack.');
  }

  const names = new Set<string>();
  for (const icon of pack.icons) {
    icon.name = icon.name.trim();
    if (icon.name.length === 0 || icon.data.length === 0 || names.has(icon.name)) {
      throw new Error('The selected icon pack contains an invalid or duplicate icon.');
    }
    names.add(icon.name);
  }
  return pack;
}

function parseIconPackEntry(data: Uint8Array): IconPackEntry {
  const entry: IconPackEntry = { name: '', data: '' };
  const cursor: ProtoCursor = { offset: 0 };
  while (cursor.offset < data.length) {
    const key = readVarint(data, cursor);
    const fieldNumber = Math.floor(key / 8);
    const wireType = key & 7;
    if (fieldNumber === 0) {
      throw new Error('The selected icon pack contains an invalid icon entry.');
    }

    if (wireType === 2) {
      const value = readLengthDelimited(data, cursor);
      if (fieldNumber === 1) {
        entry.name = TEXT_DECODER.decodeToString(value);
      } else if (fieldNumber === 2) {
        if (!isSupportedImage(value)) {
          throw new Error('The selected icon pack contains an unsupported image.');
        }
        entry.data = BASE64.encodeToStringSync(value);
      }
    } else {
      skipField(data, cursor, wireType);
    }
  }
  return entry;
}

function readVarint(data: Uint8Array, cursor: ProtoCursor): number {
  let value = 0;
  let shift = 0;
  while (cursor.offset < data.length && shift < 53) {
    const byte = data[cursor.offset];
    if (byte === undefined) {
      break;
    }
    cursor.offset++;
    value += (byte & 0x7f) * (2 ** shift);
    if ((byte & 0x80) === 0) {
      return value;
    }
    shift += 7;
  }
  throw new Error('The selected file contains an invalid icon pack encoding.');
}

function readLengthDelimited(data: Uint8Array, cursor: ProtoCursor): Uint8Array {
  const length = readVarint(data, cursor);
  if (!Number.isSafeInteger(length) || length < 0 || cursor.offset + length > data.length) {
    throw new Error('The selected file contains a truncated icon pack entry.');
  }
  const value = data.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return value;
}

function skipField(data: Uint8Array, cursor: ProtoCursor, wireType: number): void {
  if (wireType === 0) {
    readVarint(data, cursor);
    return;
  }
  if (wireType === 1) {
    cursor.offset += 8;
  } else if (wireType === 2) {
    cursor.offset += readVarint(data, cursor);
  } else if (wireType === 5) {
    cursor.offset += 4;
  } else {
    throw new Error('The selected file contains an unsupported icon pack encoding.');
  }
  if (cursor.offset > data.length) {
    throw new Error('The selected file contains a truncated icon pack entry.');
  }
}

function isSupportedImage(data: Uint8Array): boolean {
  const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (png.every((byte, index) => data[index] === byte)) {
    return true;
  }
  if (data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff) {
    return true;
  }
  if (data[0] === 0x42 && data[1] === 0x4d) {
    return true;
  }
  const webp = data[0] === 0x52 && data[1] === 0x49 && data[2] === 0x46 && data[3] === 0x46 &&
    data[8] === 0x57 && data[9] === 0x45 && data[10] === 0x42 && data[11] === 0x50;
  if (webp) {
    return true;
  }
  const hasHeifHeader = data[4] === 0x66 && data[5] === 0x74 && data[6] === 0x79 && data[7] === 0x70;
  if (!hasHeifHeader) {
    return false;
  }
  const brand = String.fromCharCode(data[8], data[9], data[10], data[11]);
  return brand === 'heic' || brand === 'heix' || brand === 'hevc' || brand === 'hevx' ||
    brand === 'mif1' || brand === 'msf1';
}
