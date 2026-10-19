import type { ReactNode } from 'react';

export type Tab =
  | 'single' | 'bulk' | 'batch' | 'defang' | 'config'
  | 'apikeys' | 'threatfeed' | 'history' | 'tools' | 'about';

interface NavItem {
  id: Tab;
  label: string;
  title: string;
  description: string;
  icon: ReactNode;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

// ── Icons (16px, 1.5 stroke) ────────────────────────────────────────────────

function Svg({ children }: { children: ReactNode }) {
  return (
    <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      {children}
    </svg>
  );
}

const icons = {
  search:   <Svg><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></Svg>,
  extract:  <Svg><path d="M4 6h16M4 12h10M4 18h7" /><path d="M17 15l3 3-3 3" /></Svg>,
  batch:    <Svg><rect x="3" y="4" width="18" height="4" rx="1" /><rect x="3" y="10" width="18" height="4" rx="1" /><rect x="3" y="16" width="18" height="4" rx="1" /></Svg>,
  feed:     <Svg><path d="M4 11a9 9 0 019 9M4 4a16 16 0 0116 16" /><circle cx="5" cy="19" r="1" /></Svg>,
  history:  <Svg><path d="M3 12a9 9 0 103-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></Svg>,
  defang:   <Svg><path d="M8 4H5v16h3M16 4h3v16h-3" /><path d="M12 15h.01" /></Svg>,
  key:      <Svg><circle cx="8" cy="15" r="4" /><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2" /></Svg>,
  tools:    <Svg><path d="M4 7h10M4 17h6M18 7h2M14 17h6" /><circle cx="16" cy="7" r="2" /><circle cx="12" cy="17" r="2" /></Svg>,
  check:    <Svg><path d="M9 11l2 2 4-4" /><rect x="3" y="3" width="18" height="18" rx="2" /></Svg>,
  info:     <Svg><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></Svg>,
  sun:      <Svg><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></Svg>,
  moon:     <Svg><path d="M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z" /></Svg>,
};

export const NAV: NavGroup[] = [
  {
    label: 'Investigate',
    items: [
      { id: 'single', label: 'Investigate', title: 'Investigate indicator', description: 'Classify an indicator, enrich it across providers and pivot to external tools.', icon: icons.search },
      { id: 'bulk', label: 'Bulk extract', title: 'Bulk extract', description: 'Pull every indicator out of logs, alerts or email bodies.', icon: icons.extract },
      { id: 'batch', label: 'Batch triage', title: 'Batch triage', description: 'Enrich a list of indicators and rank them by severity.', icon: icons.batch },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'threatfeed', label: 'Threat feed', title: 'Threat feed', description: 'Recently exploited vulnerabilities, ransomware activity and high-risk infrastructure.', icon: icons.feed },
      { id: 'history', label: 'History', title: 'Search history', description: 'Previous analyses stored in this browser.', icon: icons.history },
    ],
  },
  {
    label: 'Utilities',
    items: [
      { id: 'defang', label: 'Defang / refang', title: 'Defang / refang', description: 'Convert indicators between live and safe-to-share forms.', icon: icons.defang },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { id: 'apikeys', label: 'Integrations', title: 'Integrations', description: 'API keys for enrichment providers. Keys are written to backend/.env and never reach the browser.', icon: icons.key },
      { id: 'tools', label: 'Tool library', title: 'Tool library', description: 'Built-in and custom pivot tools, and which ones are hidden.', icon: icons.tools },
      { id: 'config', label: 'Template check', title: 'Template check', description: 'Validate every tool URL template against sample indicators. No network requests are made.', icon: icons.check },
    ],
  },
];

const ABOUT: NavItem = { id: 'about', label: 'About', title: 'About', description: 'What this toolbox does and how data flows through it.', icon: icons.info };

export const ALL_NAV_ITEMS: NavItem[] = [...NAV.flatMap(g => g.items), ABOUT];

// ── Brand mark ─────────────────────────────────────────────────────────────

function BrandMark() {
  return (
    <svg className="w-6 h-6 shrink-0" viewBox="0 0 32 32" aria-hidden>
      <rect width="32" height="32" rx="7" className="fill-fg-1" />
      <path d="M11 9H8v14h3M21 9h3v14h-3" fill="none" className="stroke-canvas" strokeWidth={2.4} strokeLinecap="square" />
      <rect x="14" y="17.5" width="4" height="4" className="fill-accent" />
    </svg>
  );
}

// ── Shell ───────────────────────────────────────────────────────────────────

interface AppShellProps {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  backendOnline: boolean | null;
  isDark: boolean;
  onToggleTheme: () => void;
  headerActions?: ReactNode;
  children: ReactNode;
}

function NavButton({ item, active, onClick }: { item: NavItem; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-current={active ? 'page' : undefined}
      className={`w-full flex items-center gap-2.5 h-8 px-2.5 rounded-md text-[13px] transition-colors ${
        active
          ? 'bg-raised text-fg-1 font-medium'
          : 'text-fg-3 hover:text-fg-1 hover:bg-raised/60'
      }`}
    >
      <span className={active ? 'text-accent-fg' : ''}>{item.icon}</span>
      {item.label}
    </button>
  );
}

function BackendStatus({ online }: { online: boolean | null }) {
  const state = online === null ? 'checking' : online ? 'online' : 'offline';
  const dot = state === 'online' ? 'bg-ok' : state === 'offline' ? 'bg-danger' : 'bg-fg-4';
  const label = state === 'online' ? 'Backend connected' : state === 'offline' ? 'Backend offline' : 'Checking backend…';
  return (
    <div className="flex items-center gap-2 text-[12px] text-fg-3" title={state === 'offline' ? 'Start it with: npm run backend:dev' : 'Local backend via /api'}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {label}
    </div>
  );
}

export function AppShell({ activeTab, onTabChange, backendOnline, isDark, onToggleTheme, headerActions, children }: AppShellProps) {
  const current = ALL_NAV_ITEMS.find(i => i.id === activeTab) ?? ALL_NAV_ITEMS[0]!;

  return (
    <div className="min-h-screen bg-canvas lg:flex">
      {/* ── Sidebar (desktop) ─────────────────────────────────────────── */}
      <aside className="hidden lg:flex flex-col w-[232px] shrink-0 h-screen sticky top-0 border-r border-line bg-surface">
        <div className="h-14 flex items-center gap-2.5 px-4 border-b border-line">
          <BrandMark />
          <div className="leading-tight">
            <p className="text-[13px] font-semibold text-fg-1">SOC Analyst Toolbox</p>
            <p className="text-[11px] text-fg-4">Local workbench</p>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-2.5 py-3 space-y-5">
          {NAV.map(group => (
            <div key={group.label}>
              <p className="px-2.5 mb-1 text-[11px] font-medium text-fg-4">{group.label}</p>
              <div className="space-y-px">
                {group.items.map(item => (
                  <NavButton key={item.id} item={item} active={activeTab === item.id} onClick={() => onTabChange(item.id)} />
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-line px-2.5 py-2.5 space-y-px">
          <NavButton item={ABOUT} active={activeTab === 'about'} onClick={() => onTabChange('about')} />
          <button
            onClick={onToggleTheme}
            className="w-full flex items-center gap-2.5 h-8 px-2.5 rounded-md text-[13px] text-fg-3 hover:text-fg-1 hover:bg-raised/60 transition-colors"
          >
            {isDark ? icons.sun : icons.moon}
            {isDark ? 'Light theme' : 'Dark theme'}
          </button>
          <div className="px-2.5 pt-2">
            <BackendStatus online={backendOnline} />
          </div>
        </div>
      </aside>

      {/* ── Top bar (mobile / tablet) ─────────────────────────────────── */}
      <div className="lg:hidden sticky top-0 z-20 bg-surface border-b border-line">
        <div className="h-12 px-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BrandMark />
            <p className="text-[13px] font-semibold text-fg-1">SOC Analyst Toolbox</p>
          </div>
          <div className="flex items-center gap-3">
            <BackendStatus online={backendOnline} />
            <button onClick={onToggleTheme} aria-label="Toggle theme" className="text-fg-3 hover:text-fg-1">
              {isDark ? icons.sun : icons.moon}
            </button>
          </div>
        </div>
        <nav className="flex overflow-x-auto px-2 gap-1 pb-2">
          {ALL_NAV_ITEMS.map(item => (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`h-7 px-2.5 rounded-md text-[12px] whitespace-nowrap ${
                activeTab === item.id ? 'bg-raised text-fg-1 font-medium' : 'text-fg-3'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </div>

      {/* ── Main ───────────────────────────────────────────────────────── */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="border-b border-line bg-surface">
          <div className="max-w-[1280px] mx-auto px-6 py-4 flex items-start justify-between gap-6">
            <div className="min-w-0">
              <h1 className="text-[17px] font-semibold text-fg-1 tracking-[-0.01em]">{current.title}</h1>
              <p className="text-[13px] text-fg-3 mt-0.5">{current.description}</p>
            </div>
            {headerActions && <div className="shrink-0 flex items-center gap-2">{headerActions}</div>}
          </div>
        </header>

        <main className="flex-1 w-full max-w-[1280px] mx-auto px-6 py-5">
          {children}
        </main>

        <footer className="max-w-[1280px] w-full mx-auto px-6 py-4 text-[11px] text-fg-4 flex flex-wrap gap-x-4 gap-y-1">
          <span>Enrichment runs through the local backend. No telemetry.</span>
          <span>External tool links may submit indicators to third parties — check each tool’s exposure label.</span>
        </footer>
      </div>
    </div>
  );
}
