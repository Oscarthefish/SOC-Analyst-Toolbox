import { useState } from 'react';
import { copyToClipboard } from '../lib/clipboard';

interface CopyButtonProps {
  text: string;
  label?: string;
  className?: string;
  iconOnly?: boolean;
}

export function CopyButton({ text, label = 'Copy', className = '', iconOnly = false }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const success = await copyToClipboard(text);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    }
  };

  if (iconOnly) {
    return (
      <button
        onClick={handleCopy}
        title={`Copy ${label}`}
        className={`inline-flex items-center justify-center w-7 h-7 rounded-lg border transition-colors ${
          copied
            ? 'border-ok-line bg-ok-bg text-ok-fg'
            : 'border-line bg-surface text-fg-3 hover:border-line-strong hover:text-fg-2'
        } ${className}`}
      >
        {copied ? (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.6}>
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
          </svg>
        )}
      </button>
    );
  }

  return (
    <button
      onClick={handleCopy}
      title={`Copy ${label}`}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
        copied
          ? 'border-ok-line bg-ok-bg text-ok-fg'
          : 'border-line bg-surface text-fg-2 hover:border-line-strong hover:text-fg-1'
      } ${className}`}
    >
      {copied ? (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          Copied
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.6}>
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
          </svg>
          {label}
        </>
      )}
    </button>
  );
}
