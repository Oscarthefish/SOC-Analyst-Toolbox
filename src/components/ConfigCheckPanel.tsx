import type { Tool } from '../types/tool';
import { buildTemplateVars, applyTemplate, safeHref } from '../lib/template';
import { detectIoc } from '../lib/detectIoc';

interface ConfigCheckPanelProps {
  tools: Tool[];
  customToolCount: number;
}

const SAMPLE_IOCS = [
  { label: 'IPv4',   value: '8.8.8.8' },
  { label: 'Domain', value: 'example.com' },
  { label: 'URL',    value: 'https://login.example.com/reset?token=abc' },
  { label: 'SHA256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { label: 'Email',  value: 'user@example.com' },
  { label: 'ASN',    value: 'AS15169' },
  { label: 'CIDR',   value: '192.168.1.0/24' },
];

type UrlStatus = 'ok' | 'home' | 'broken';

function checkUrl(template: string, renderedUrl: string): UrlStatus {
  if (/\{\{[^}]+\}\}/.test(renderedUrl)) return 'broken';
  if (!renderedUrl.startsWith('http')) return 'broken';
  if (renderedUrl === template && template.includes('{{')) return 'home';
  if (!template.includes('{{')) return 'home';
  return 'ok';
}

export function ConfigCheckPanel({ tools, customToolCount }: ConfigCheckPanelProps) {
  const samples = SAMPLE_IOCS.map(s => ({
    ...s,
    detected: detectIoc(s.value),
  }));

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="wb-card p-5">
        <div className="flex items-start justify-between gap-4 mb-3">
          <div>
            <p className="text-xs text-fg-3 mt-0.5">Tool sources</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs px-2 py-0.5 rounded bg-raised border border-line text-fg-2 font-medium">
              {tools.length - customToolCount} built-in
            </span>
            <span className={`text-xs px-2 py-0.5 rounded border font-medium ${
              customToolCount > 0
                ? 'bg-ok-bg border-ok-line text-ok-fg'
                : 'bg-raised border-line text-fg-4'
            }`}>
              {customToolCount} custom
            </span>
          </div>
        </div>

        {customToolCount === 0 && (
          <p className="text-xs text-fg-3">
            No custom tools yet. Add internal tools (SIEM, EDR, ticketing) from the <strong className="font-medium text-fg-2">Tool library</strong> page; they are saved to <code className="font-mono text-[11px]">backend/data/customTools.json</code>.
          </p>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-fg-3">
        <div className="flex items-center gap-1.5">
          <span className="text-ok-fg font-bold text-sm leading-none">✓</span>
          <span>URL renders correctly</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-warn-fg font-bold text-sm leading-none">—</span>
          <span>Home URL / manual lookup</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-danger-fg font-bold text-sm leading-none">✗</span>
          <span>Template produces broken URL</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-fg-4 font-bold text-sm leading-none">·</span>
          <span>Type not in inputTypes</span>
        </div>
      </div>

      {/* Tool table */}
      <div className="wb-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-line bg-inset">
                <th className="text-left py-2.5 px-4 wb-label">Tool</th>
                <th className="text-left py-2.5 px-3 wb-label hidden sm:table-cell">Category</th>
                {samples.map(s => (
                  <th key={s.label} className="text-center py-2.5 px-2 wb-label min-w-[56px]">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tools.map((tool, i) => (
                <tr
                  key={tool.id}
                  className={`border-b border-line-soft hover:bg-inset transition-colors ${
                    i % 2 === 0 ? 'bg-surface' : 'bg-inset'
                  }`}
                >
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-1.5">
                      <span className="text-fg-1 font-medium">{tool.name}</span>
                      {tool.id.startsWith('custom-') && (
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-ok-bg border border-ok-line text-ok-fg font-medium">
                          custom
                        </span>
                      )}
                    </div>
                    <div className="text-fg-3 mt-0.5 truncate max-w-[220px] font-mono text-[11px]" title={tool.urlTemplate}>
                      {tool.urlTemplate.replace('https://', '').replace('http://', '').slice(0, 45)}
                      {tool.urlTemplate.length > 55 ? '…' : ''}
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-fg-3 hidden sm:table-cell">{tool.category}</td>
                  {samples.map(s => {
                    const supportsType = tool.inputTypes.includes(s.detected.type);
                    if (!supportsType) {
                      return (
                        <td key={s.label} className="py-2.5 px-2 text-center">
                          <span className="text-fg-4 text-base leading-none">·</span>
                        </td>
                      );
                    }
                    const vars = buildTemplateVars(s.detected);
                    const rendered = applyTemplate(tool.urlTemplate, vars);
                    const status = checkUrl(tool.urlTemplate, rendered);
                    return (
                      <td key={s.label} className="py-2.5 px-2 text-center">
                        {status === 'ok' && (
                          <a
                            href={safeHref(rendered)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-ok-fg hover:text-ok-fg font-bold transition-colors"
                            title={rendered}
                          >
                            ✓
                          </a>
                        )}
                        {status === 'home' && (
                          <a
                            href={safeHref(tool.urlTemplate)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-warn-fg hover:text-warn-fg font-bold transition-colors"
                            title="Home/manual URL — no template variable applied"
                          >
                            —
                          </a>
                        )}
                        {status === 'broken' && (
                          <span className="text-danger-fg font-bold" title={`Broken: ${rendered}`}>
                            ✗
                          </span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <p className="text-xs text-fg-4">
        Clicking ✓ or — opens the tool in a new tab using the sample IOC. This is for validation only — no data is sent automatically.
      </p>
    </div>
  );
}
