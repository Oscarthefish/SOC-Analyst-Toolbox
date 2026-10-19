/** Shared IP validation for detection and extraction. */

export function isIpv4(value: string): boolean {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  return value.split('.').every(p => Number(p) <= 255);
}

export function isIpv4Cidr(value: string): boolean {
  const m = /^(.+)\/(\d{1,2})$/.exec(value);
  return m !== null && isIpv4(m[1]!) && Number(m[2]) <= 32;
}

/**
 * Strict IPv6 check using the WHATWG URL parser, which validates group counts and
 * "::" compression. Rejects look-alikes such as clock times ("12:30:45").
 */
export function isIpv6(value: string): boolean {
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}
