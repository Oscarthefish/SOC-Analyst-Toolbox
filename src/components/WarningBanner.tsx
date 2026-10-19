interface WarningBannerProps {
  type: 'info' | 'warning' | 'danger';
  message: string;
  details?: string;
}

const styles = {
  info:    'bg-accent-bg border-accent-line text-accent-fg',
  warning: 'bg-warn-bg border-warn-line text-warn-fg',
  danger:  'bg-danger-bg border-danger-line text-danger-fg',
};

const icons = {
  info: (
    <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="10" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 16v-4m0-4h.01" />
    </svg>
  ),
  warning: (
    <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01" />
    </svg>
  ),
  danger: (
    <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="10" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01" />
    </svg>
  ),
};

export function WarningBanner({ type, message, details }: WarningBannerProps) {
  return (
    <div className={`flex gap-2.5 p-3 rounded-lg border text-sm ${styles[type]}`}>
      {icons[type]}
      <div>
        <p className="font-semibold">{message}</p>
        {details && <p className="mt-0.5 opacity-80 text-xs font-normal">{details}</p>}
      </div>
    </div>
  );
}
