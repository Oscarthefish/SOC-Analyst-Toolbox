export type IocType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'email'
  | 'asn'
  | 'cidr'
  | 'cve'
  | 'secret'
  | 'unknown';

export interface UrlExtract {
  fullUrl: string;
  scheme: string;
  hostname: string;
  domain: string;
  path: string;
  query: string;
  queryParamNames: string[];
  encodedUrl: string;
  encodedHostname: string;
  isSensitive: boolean;
  sensitiveTerms: string[];
}

export interface DetectedIoc {
  original: string;
  trimmed: string;
  type: IocType;
  confidence: 'high' | 'medium' | 'low';
  normalised: string;
  urlExtract?: UrlExtract;
  isSensitiveUrl?: boolean;
  sensitiveUrlWarning?: string;
  isEmailHeader?: boolean;
  isCredential?: boolean;
  credentialType?: string;
  credentialWarning?: string;
}
