import type { DetectedIoc } from '../types/ioc';

/**
 * Returns the best searchable value for a detected IOC.
 * For URLs: use the hostname/domain.
 * For everything else: use normalised.
 */
export function getBestSearchValue(ioc: DetectedIoc): string {
  if (ioc.type === 'url' && ioc.urlExtract) {
    return ioc.urlExtract.domain;
  }
  return ioc.normalised;
}

export function getDisplayLabel(ioc: DetectedIoc): string {
  const type = ioc.type.toUpperCase();
  return `${type}: ${ioc.normalised}`;
}
