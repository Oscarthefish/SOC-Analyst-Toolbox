const TTL: Record<string, number> = {
  greynoise:      15,
  abuseipdb:      30,
  virustotal:     60,
  urlscan:        60,
  malwarebazaar:  60,
  threatfox:      60,
  otx:            60,
  ipapi:          60,
  ipinfo:         60,
  torproject:     60,
  shodan:        120,
  censys:        120,
  bgpview:       360,
  hybridanalysis:240,
  pulsedive:      60,
  urlhaus:        60,
  safebrowsing:   60,
  hibp:          120,
  whois:        1440,
  cisakev:        60,
  crtsh:         180,
  dns:            10,
  ransomwarelive: 25,
  hunter:        720,
  wayback:       240,
};

export function getProviderTtl(providerId: string, fallback: number): number {
  return TTL[providerId] ?? fallback;
}
