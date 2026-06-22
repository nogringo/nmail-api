const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

export function decodeNpub(value: string): string | null {
  const decoded = decodeBech32(value)
  if (!decoded || decoded.hrp !== 'npub') return null

  const bytes = convertBits(decoded.data, 5, 8, false)
  if (!bytes || bytes.length !== 32) return null

  return Buffer.from(bytes).toString('hex')
}

// A local part is "encoded" when it decodes to a pubkey on its own (hex64,
// npub or base36). Such addresses resolve without the database, so they are not
// aliases and are not claimable.
export function decodeEncodedLocalPart(localPart: string): string | null {
  if (/^[0-9a-f]{64}$/.test(localPart)) return localPart

  const npub = decodeNpub(localPart)
  if (npub) return npub

  return decodeBase36Pubkey(localPart)
}

export function isEncodedLocalPart(localPart: string): boolean {
  return decodeEncodedLocalPart(localPart) !== null
}

export function decodeBase36Pubkey(value: string): string | null {
  if (value.length < 48 || value.length > 52) return null
  if (!/^[0-9a-z]+$/.test(value)) return null

  let pubkey = 0n
  for (const char of value) {
    const digit = Number.parseInt(char, 36)
    if (!Number.isInteger(digit) || digit < 0 || digit >= 36) return null
    pubkey = pubkey * 36n + BigInt(digit)
  }

  if (pubkey >= 1n << 256n) return null

  return pubkey.toString(16).padStart(64, '0')
}

function decodeBech32(value: string): { hrp: string; data: number[] } | null {
  if (!value || value !== value.toLowerCase()) return null

  const separator = value.lastIndexOf('1')
  if (separator <= 0 || separator + 7 > value.length) return null

  const hrp = value.slice(0, separator)
  const payload = value.slice(separator + 1)
  const values: number[] = []

  for (const char of payload) {
    const index = BECH32_CHARSET.indexOf(char)
    if (index === -1) return null
    values.push(index)
  }

  if (!verifyChecksum(hrp, values)) return null

  return { hrp, data: values.slice(0, -6) }
}

function verifyChecksum(hrp: string, data: number[]): boolean {
  return polymod([...expandHrp(hrp), ...data]) === 1
}

function expandHrp(hrp: string): number[] {
  const expanded: number[] = []
  for (const char of hrp) expanded.push(char.charCodeAt(0) >> 5)
  expanded.push(0)
  for (const char of hrp) expanded.push(char.charCodeAt(0) & 31)
  return expanded
}

function polymod(values: number[]): number {
  let checksum = 1

  for (const value of values) {
    const top = checksum >> 25
    checksum = ((checksum & 0x1ffffff) << 5) ^ value

    for (let index = 0; index < BECH32_GENERATORS.length; index += 1) {
      if ((top >> index) & 1) checksum ^= BECH32_GENERATORS[index]
    }
  }

  return checksum
}

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] | null {
  let accumulator = 0
  let bits = 0
  const maxValue = (1 << toBits) - 1
  const converted: number[] = []

  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) return null

    accumulator = (accumulator << fromBits) | value
    bits += fromBits

    while (bits >= toBits) {
      bits -= toBits
      converted.push((accumulator >> bits) & maxValue)
    }
  }

  if (pad) {
    if (bits > 0) converted.push((accumulator << (toBits - bits)) & maxValue)
  } else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue)) {
    return null
  }

  return converted
}
