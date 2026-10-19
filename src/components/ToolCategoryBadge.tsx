import { toolFamily } from '../lib/toolFamily';
import type { ToolFamily } from '../lib/toolFamily';

export const FAMILY_BADGE: Record<ToolFamily, string> = {
  intel: 'bg-c1-bg text-c1-fg border-c1/25',
  web: 'bg-c2-bg text-c2-fg border-c2/25',
  malware: 'bg-c3-bg text-c3-fg border-c3/25',
  infra: 'bg-c5-bg text-c5-fg border-c5/25',
  business: 'bg-c4-bg text-c4-fg border-c4/25',
};

export const FAMILY_FILL: Record<ToolFamily, string> = {
  intel: 'bg-c1', web: 'bg-c2', malware: 'bg-c3', infra: 'bg-c5', business: 'bg-c4',
};

export function ToolCategoryBadge({ category }: { category: string }) {
  return (
    <span className={`inline-flex items-center px-1.5 h-[18px] rounded border text-[10px] font-semibold whitespace-nowrap ${FAMILY_BADGE[toolFamily(category)]}`}>
      {category}
    </span>
  );
}
