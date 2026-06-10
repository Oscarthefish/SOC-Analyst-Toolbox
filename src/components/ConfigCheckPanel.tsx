import type { Tool } from '../types/tool';
import { buildTemplateVars, applyTemplate } from '../lib/template';
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
            <h2 className="text-[15px] font-semibold text-[#101828]">Config Check</h2>
            <p className="text-xs text-[#667085] mt-0.5">
              Validates URL templates for all configured tools against sample IOCs. No network requests are made.
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs px-2 py-0.5 rounded-full bg-[#f2f4f7] border border-[#e4e7ec] text-[#344054] font-medium">
              {tools.length - customToolCount} built-in
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
              customToolCount > 0
                ? 'bg-[#ecfdf3] border-[#abefc6] text-[#067647]'
                : 'bg-[#f2f4f7] border-[#e4e7ec] text-[#98a2b3]'
            }`}>
              {customToolCount} custom
            </span>
          </div>
        </div>

        {customToolCount === 0 && (
          <div className="bg-[#fffaeb] border border-[#fedf89] rounded-lg px-3 py-2.5 text-xs text-[#b54708] flex items-start gap-2">
            <svg className="w-3.5 h-3.5 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>
              No custom tools loaded. To add custom tools, copy{' '}
              <code className="bg-[#fef0c7] border border-[#fedf89] text-[#7a2e08] px-1 py-0.5 rounded font-mono text-[11px]">
                src/data/customTools.example.json
              </code>
              {' '}to{' '}
              <code className="bg-[#fef0c7] border border-[#fedf89] text-[#7a2e08] px-1 py-0.5 rounded font-mono text-[11px]">
                src/data/customTools.json
              </code>
              {' '}and edit with your internal tool URLs.
            </span>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#667085]">
        <div className="flex items-center gap-1.5">
          <span className="text-[#067647] font-bold text-sm leading-none">✓</span>
          <span>URL renders correctly</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-[#b54708] font-bold text-sm leading-none">—</span>
          <span>Home URL / manual lookup</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-[#b42318] font-bold text-sm leading-none">✗</span>
          <span>Template produces broken URL</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-[#d0d5dd] font-bold text-sm leading-none">·</span>
          <span>Type not in inputTypes</span>
        </div>
      </div>

      {/* Tool table */}
      <div className="wb-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#e4e7ec] bg-[#fafbfc]">
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
                  className={`border-b border-[#f2f4f7] hover:bg-[#fafbfc] transition-colors ${
                    i % 2 === 0 ? 'bg-white' : 'bg-[#fafbfc]'
                  }`}
                >
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[#101828] font-medium">{tool.name}</span>
                      {tool.id.startsWith('custom-') && (
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-[#ecfdf3] border border-[#abefc6] text-[#067647] font-medium">
                          custom
                        </span>
                      )}
                    </div>
                    <div className="text-[#667085] mt-0.5 truncate max-w-[220px] font-mono text-[11px]" title={tool.urlTemplate}>
                      {tool.urlTemplate.replace('https://', '').replace('http://', '').slice(0, 45)}
                      {tool.urlTemplate.length > 55 ? '…' : ''}
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-[#667085] hidden sm:table-cell">{tool.category}</td>
                  {samples.map(s => {
                    const supportsType = tool.inputTypes.includes(s.detected.type);
                    if (!supportsType) {
                      return (
                        <td key={s.label} className="py-2.5 px-2 text-center">
                          <span className="text-[#d0d5dd] text-base leading-none">·</span>
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
                            href={rendered}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#067647] hover:text-[#079455] font-bold transition-colors"
                            title={rendered}
                          >
                            ✓
                          </a>
                        )}
                        {status === 'home' && (
                          <a
                            href={tool.urlTemplate}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#b54708] hover:text-[#dc6803] font-bold transition-colors"
                            title="Home/manual URL — no template variable applied"
                          >
                            —
                          </a>
                        )}
                        {status === 'broken' && (
                          <span className="text-[#b42318] font-bold" title={`Broken: ${rendered}`}>
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

      <p className="text-xs text-[#98a2b3]">
        Clicking ✓ or — opens the tool in a new tab using the sample IOC. This is for validation only — no data is sent automatically.
      </p>
    </div>
  );
}
