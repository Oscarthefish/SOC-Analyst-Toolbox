import { useState, useMemo } from 'react';
import type { Tool, SubmissionRisk, RequiresAccount } from '../types/tool';
import type { IocType } from '../types/ioc';
import type { Workflow } from '../types/workflow';
import workflowsData from '../data/workflows.json';
import { DEFAULT_TOOL_FORM, validateToolForm, formToTool } from '../lib/customTools';
import type { ToolFormState } from '../lib/customTools';

interface Props {
  builtinTools: Tool[];
  customTools: Tool[];
  hiddenToolIds: Set<string>;
  saving: boolean;
  /** Resolves false if the backend rejected or couldn't store the change */
  onSaveCustomTools: (tools: Tool[]) => Promise<boolean>;
  onToggleHidden: (id: string) => void;
}

// ── Static reference data ─────────────────────────────────────────────────────

const ALL_IOC_TYPES: { value: IocType; label: string }[] = [
  { value: 'ipv4',   label: 'IPv4' },
  { value: 'ipv6',   label: 'IPv6' },
  { value: 'domain', label: 'Domain' },
  { value: 'url',    label: 'URL' },
  { value: 'md5',    label: 'MD5' },
  { value: 'sha1',   label: 'SHA-1' },
  { value: 'sha256', label: 'SHA-256' },
  { value: 'email',  label: 'Email' },
  { value: 'asn',    label: 'ASN' },
  { value: 'cidr',   label: 'CIDR' },
  { value: 'cve',    label: 'CVE' },
];

// Derived from the workflow definitions so names never drift
const ALL_WORKFLOWS = (workflowsData as Workflow[]).map(w => ({ id: w.id, name: w.name }));

const CATEGORIES = [
  'Custom',
  'Analysis / Decoding',
  'Business OSINT',
  'Certificate / OSINT',
  'DNS / OSINT',
  'Dark Web / Credential',
  'Dark Web / OSINT',
  'Email / DNS',
  'Email Analysis',
  'Exposure',
  'Fraud / Proxy Detection',
  'IP Intelligence',
  'Malware / URL',
  'Malware Analysis',
  'OSINT',
  'Phishing Analysis',
  'Phishing Reporting',
  'Proxy / VPN Detection',
  'Ransomware Intelligence',
  'Reputation',
  'Sandbox',
  'Threat Intelligence',
  'URL Analysis',
  'WHOIS / Registration',
  'Web Categorisation',
];

const TEMPLATE_VARS = [
  { v: '{{value}}',        desc: 'IOC value (any type)' },
  { v: '{{encodedValue}}', desc: 'URL-encoded IOC value' },
  { v: '{{domain}}',       desc: 'Domain name' },
  { v: '{{ip}}',           desc: 'IP address' },
  { v: '{{hash}}',         desc: 'File hash (MD5/SHA1/SHA256)' },
  { v: '{{url}}',          desc: 'Full URL' },
  { v: '{{email}}',        desc: 'Email address' },
  { v: '{{asn}}',          desc: 'ASN (e.g. AS12345)' },
  { v: '{{cidr}}',         desc: 'CIDR range' },
];

// ── Sub-components ────────────────────────────────────────────────────────────

function Checkbox({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="inline-flex items-center gap-1.5 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
        className="w-3.5 h-3.5 rounded border-line-strong text-accent-fg focus:ring-accent/20"
      />
      <span className="text-[12px] text-fg-2">{label}</span>
    </label>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return <p className="text-[11px] font-semibold text-fg-2 uppercase tracking-wide mb-1.5">{children}</p>;
}

function InputField({ value, onChange, placeholder, error }: {
  value: string; onChange: (v: string) => void; placeholder?: string; error?: string;
}) {
  return (
    <div>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full text-[13px] px-3 py-2 border rounded-lg bg-surface text-fg-1 placeholder-fg-4 focus:outline-none focus:ring-2 transition-colors ${
          error ? 'border-danger-line focus:border-danger focus:ring-danger/10' : 'border-line-strong focus:border-accent focus:ring-accent/10'
        }`}
      />
      {error && <p className="text-[11px] text-danger-fg mt-1">{error}</p>}
    </div>
  );
}

function CategoryBadge({ category }: { category: string }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-raised border border-line text-fg-2">
      {category}
    </span>
  );
}

// ── Custom tool row ───────────────────────────────────────────────────────────

function CustomToolRow({ tool, onDelete }: { tool: Tool; onDelete: () => void }) {
  return (
    <div className="flex items-start gap-3 p-4 border border-line rounded-xl bg-surface">
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-1">
          <span className="text-[13px] font-semibold text-fg-1">{tool.name}</span>
          <CategoryBadge category={tool.category} />
        </div>
        <p className="text-[11px] font-mono text-fg-3 truncate mb-2">{tool.urlTemplate}</p>
        <div className="flex flex-wrap gap-1.5">
          {tool.inputTypes.map(t => (
            <span key={t} className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-accent-bg border border-accent-line text-accent-fg">
              {t.toUpperCase()}
            </span>
          ))}
          {tool.workflows.map(w => {
            const wf = ALL_WORKFLOWS.find(x => x.id === w);
            return wf ? (
              <span key={w} className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-inset border border-line text-fg-3">
                {wf.name}
              </span>
            ) : null;
          })}
        </div>
      </div>
      <button
        onClick={onDelete}
        className="shrink-0 text-xs font-medium px-3 py-1.5 rounded-lg border border-danger-line bg-danger-bg text-danger-fg hover:bg-danger-bg transition-colors"
      >
        Delete
      </button>
    </div>
  );
}

// ── Built-in tool row ─────────────────────────────────────────────────────────

function BuiltinToolRow({ tool, hidden, onToggle }: { tool: Tool; hidden: boolean; onToggle: () => void }) {
  return (
    <div className={`flex items-start gap-3 px-4 py-3 border-b border-line-soft last:border-0 transition-opacity ${hidden ? 'opacity-50' : ''}`}>
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-0.5">
          <span className="text-[13px] font-semibold text-fg-1">{tool.name}</span>
          <CategoryBadge category={tool.category} />
        </div>
        <p className="text-[12px] text-fg-3 truncate">{tool.description}</p>
      </div>
      <button
        onClick={onToggle}
        className={`shrink-0 inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded border transition-colors ${
          hidden
            ? 'bg-raised border-line text-fg-4 hover:border-line-strong hover:text-fg-3'
            : 'bg-ok-bg border-ok-line text-ok-fg hover:bg-ok-bg'
        }`}
      >
        <span className={`w-1.5 h-1.5 rounded-full ${hidden ? 'bg-fg-4' : 'bg-ok'}`} />
        {hidden ? 'Hidden' : 'Visible'}
      </button>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export function ToolsManagementPanel({ builtinTools, customTools, hiddenToolIds, saving, onSaveCustomTools, onToggleHidden }: Props) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<ToolFormState>(DEFAULT_TOOL_FORM);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [showOptional, setShowOptional] = useState(false);
  const [search, setSearch] = useState('');
  const [showHiddenOnly, setShowHiddenOnly] = useState(false);
  const [showVarRef, setShowVarRef] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const hiddenCount = useMemo(() => {
    return builtinTools.filter(t => hiddenToolIds.has(t.id)).length;
  }, [builtinTools, hiddenToolIds]);

  const filteredBuiltin = useMemo(() => {
    const q = search.toLowerCase();
    return builtinTools.filter(t => {
      const matchSearch = !q || t.name.toLowerCase().includes(q) || t.category.toLowerCase().includes(q) || t.description.toLowerCase().includes(q);
      const matchFilter = !showHiddenOnly || hiddenToolIds.has(t.id);
      return matchSearch && matchFilter;
    });
  }, [builtinTools, search, showHiddenOnly, hiddenToolIds]);

  function patchForm(patch: Partial<ToolFormState>) {
    setForm(prev => ({ ...prev, ...patch }));
  }

  function toggleIocType(type: IocType) {
    patchForm({
      inputTypes: form.inputTypes.includes(type)
        ? form.inputTypes.filter(t => t !== type)
        : [...form.inputTypes, type],
    });
  }

  function toggleWorkflow(id: string) {
    patchForm({
      workflows: form.workflows.includes(id)
        ? form.workflows.filter(w => w !== id)
        : [...form.workflows, id],
    });
  }

  function validate(): boolean {
    const e = validateToolForm(form);
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function handleSave() {
    if (!validate()) return;
    setSaveError(null);
    const allIds = new Set([...builtinTools.map(t => t.id), ...customTools.map(t => t.id)]);
    const ok = await onSaveCustomTools([...customTools, formToTool(form, allIds)]);
    if (!ok) {
      // Keep the form so nothing typed is lost
      setSaveError('The tool could not be saved. Check that the backend is running, then try again.');
      return;
    }
    setForm(DEFAULT_TOOL_FORM);
    setErrors({});
    setShowForm(false);
    setShowOptional(false);
  }

  function handleCancel() {
    setSaveError(null);
    setForm(DEFAULT_TOOL_FORM);
    setErrors({});
    setShowForm(false);
    setShowOptional(false);
  }

  async function handleDelete(id: string) {
    setSaveError(null);
    const ok = await onSaveCustomTools(customTools.filter(t => t.id !== id));
    if (!ok) setSaveError('The tool could not be deleted. Check that the backend is running, then try again.');
  }

  return (
    <div className="space-y-4">

      {/* ── Custom tools ─────────────────────────────────────────────────── */}
      <div className="wb-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="wb-label">Custom Tools</p>
            {customTools.length > 0 && (
              <p className="text-[12px] text-fg-4 mt-0.5">{customTools.length} custom tool{customTools.length !== 1 ? 's' : ''} added</p>
            )}
          </div>
          {!showForm && (
            <button
              onClick={() => setShowForm(true)}
              className="inline-flex items-center gap-1.5 text-[13px] font-semibold px-3.5 py-2 rounded-lg bg-accent text-white hover:bg-accent-strong transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2.2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              Add Custom Tool
            </button>
          )}
        </div>

        {/* Add form */}
        {showForm && (
          <div className="border border-line rounded-xl p-5 bg-inset mb-4 space-y-4">
            <p className="text-[13px] font-semibold text-fg-1">New Custom Tool</p>

            {/* Name + Category */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <FieldLabel>Tool name *</FieldLabel>
                <InputField
                  value={form.name}
                  onChange={v => patchForm({ name: v })}
                  placeholder="e.g. Internal Threat DB"
                  error={errors.name}
                />
              </div>
              <div>
                <FieldLabel>Category</FieldLabel>
                <select
                  value={form.category}
                  onChange={e => patchForm({ category: e.target.value })}
                  className="w-full text-[13px] px-3 py-2 border border-line-strong rounded-lg bg-surface text-fg-1 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/10"
                >
                  {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            </div>

            {/* URL Template */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <FieldLabel>URL Template *</FieldLabel>
                <button
                  onClick={() => setShowVarRef(v => !v)}
                  className="text-[11px] text-accent-fg hover:underline"
                >
                  {showVarRef ? 'Hide' : 'Show'} template variables
                </button>
              </div>
              <InputField
                value={form.urlTemplate}
                onChange={v => patchForm({ urlTemplate: v })}
                placeholder="https://example.com/search?q={{value}}"
                error={errors.urlTemplate}
              />
              {showVarRef && (
                <div className="mt-2 p-3 rounded-lg border border-line bg-surface">
                  <p className="text-[11px] font-semibold text-fg-3 uppercase tracking-wide mb-2">Available variables</p>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1">
                    {TEMPLATE_VARS.map(({ v, desc }) => (
                      <div key={v} className="flex items-baseline gap-2">
                        <code className="text-[11px] font-mono text-accent-fg shrink-0">{v}</code>
                        <span className="text-[11px] text-fg-4">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* IOC Types */}
            <div>
              <FieldLabel>Supported IOC types *</FieldLabel>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                {ALL_IOC_TYPES.map(({ value, label }) => (
                  <Checkbox
                    key={value}
                    checked={form.inputTypes.includes(value)}
                    onChange={() => toggleIocType(value)}
                    label={label}
                  />
                ))}
              </div>
              {errors.inputTypes && <p className="text-[11px] text-danger-fg mt-1">{errors.inputTypes}</p>}
            </div>

            {/* Workflows */}
            <div>
              <FieldLabel>Workflows to include in</FieldLabel>
              <div className="grid grid-cols-2 gap-x-6 gap-y-2">
                {ALL_WORKFLOWS.map(({ id, name }) => (
                  <Checkbox
                    key={id}
                    checked={form.workflows.includes(id)}
                    onChange={() => toggleWorkflow(id)}
                    label={name}
                  />
                ))}
              </div>
            </div>

            {/* Optional fields toggle */}
            <button
              onClick={() => setShowOptional(v => !v)}
              className="text-[12px] text-fg-3 hover:text-fg-2 flex items-center gap-1.5 transition-colors"
            >
              <svg className={`w-3.5 h-3.5 transition-transform ${showOptional ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 18l6-6-6-6" />
              </svg>
              {showOptional ? 'Hide' : 'Show'} optional fields (description, why use, risk note…)
            </button>

            {showOptional && (
              <div className="space-y-3 pt-1 border-t border-line-soft">
                <div>
                  <FieldLabel>Description</FieldLabel>
                  <InputField value={form.description} onChange={v => patchForm({ description: v })} placeholder="Brief description of what this tool does" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <FieldLabel>Why use</FieldLabel>
                    <InputField value={form.whyUse} onChange={v => patchForm({ whyUse: v })} placeholder="e.g. Fast reputation check" />
                  </div>
                  <div>
                    <FieldLabel>Look for</FieldLabel>
                    <InputField value={form.lookFor} onChange={v => patchForm({ lookFor: v })} placeholder="e.g. Threat score, hits" />
                  </div>
                </div>
                <div>
                  <FieldLabel>Risk note</FieldLabel>
                  <InputField value={form.riskNote} onChange={v => patchForm({ riskNote: v })} placeholder="e.g. Submits IOC to external service" />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <FieldLabel>Submission risk</FieldLabel>
                    <select
                      value={form.submissionRisk}
                      onChange={e => patchForm({ submissionRisk: e.target.value as SubmissionRisk })}
                      className="w-full text-[13px] px-3 py-2 border border-line-strong rounded-lg bg-surface text-fg-1 focus:outline-none focus:border-accent"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>
                  <div>
                    <FieldLabel>Requires account</FieldLabel>
                    <select
                      value={form.requiresAccount}
                      onChange={e => patchForm({ requiresAccount: e.target.value as RequiresAccount })}
                      className="w-full text-[13px] px-3 py-2 border border-line-strong rounded-lg bg-surface text-fg-1 focus:outline-none focus:border-accent"
                    >
                      <option value="none">None</option>
                      <option value="free_account">Free account</option>
                      <option value="trial">Trial</option>
                      <option value="paid">Paid</option>
                      <option value="mixed">Mixed</option>
                    </select>
                  </div>
                  <div>
                    <FieldLabel>Tags (comma-separated)</FieldLabel>
                    <InputField value={form.tags} onChange={v => patchForm({ tags: v })} placeholder="e.g. reputation, ip" />
                  </div>
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-line-soft">
              {saveError && <p role="alert" className="mr-auto text-xs text-danger-fg">{saveError}</p>}
              <button
                onClick={handleCancel}
                className="text-[13px] font-medium px-4 py-2 rounded-lg border border-line bg-surface text-fg-2 hover:border-line-strong transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => { void handleSave(); }}
                disabled={saving}
                className="text-[13px] font-semibold px-4 py-2 rounded-lg bg-accent text-white hover:bg-accent-strong disabled:opacity-60 transition-colors"
              >
                {saving ? 'Saving…' : 'Save Tool'}
              </button>
            </div>
          </div>
        )}

        {saveError && !showForm && <p role="alert" className="text-xs text-danger-fg">{saveError}</p>}

        {/* Custom tool list */}
        {customTools.length === 0 ? (
          <div className={`flex items-center justify-center py-10 ${showForm ? 'hidden' : ''}`}>
            <div className="text-center space-y-2">
              <div className="w-10 h-10 rounded-xl bg-raised flex items-center justify-center mx-auto">
                <svg className="w-5 h-5 text-fg-4" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
                </svg>
              </div>
              <p className="text-[13px] text-fg-3">No custom tools yet.</p>
              <p className="text-[12px] text-fg-4">Click "Add Custom Tool" to add your own investigation links.</p>
            </div>
          </div>
        ) : !showForm ? (
          <div className="space-y-2">
            {customTools.map(tool => (
              <CustomToolRow
                key={tool.id}
                tool={tool}
                onDelete={() => { void handleDelete(tool.id); }}
              />
            ))}
          </div>
        ) : null}
      </div>

      {/* ── Built-in tools ────────────────────────────────────────────────── */}
      <div className="wb-card overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-line-soft">
          <div>
            <p className="wb-label">Built-in Tools</p>
            <p className="text-[12px] text-fg-4 mt-0.5">
              {builtinTools.length} tools
              {hiddenCount > 0 && <> · <span className="text-warn-fg">{hiddenCount} hidden</span></>}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {hiddenCount > 0 && (
              <button
                onClick={() => setShowHiddenOnly(v => !v)}
                className={`text-[12px] font-medium px-3 py-1.5 rounded-lg border transition-colors ${
                  showHiddenOnly
                    ? 'border-warn-line bg-warn-bg text-warn-fg'
                    : 'border-line bg-surface text-fg-3 hover:border-line-strong'
                }`}
              >
                {showHiddenOnly ? 'Show all' : `Show ${hiddenCount} hidden`}
              </button>
            )}
            <div className="relative">
              <svg className="w-4 h-4 text-fg-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
                <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" />
              </svg>
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search tools…"
                className="pl-9 pr-3 py-1.5 text-[13px] border border-line rounded-lg bg-surface text-fg-1 placeholder-fg-4 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/10 w-52 transition-colors"
              />
            </div>
          </div>
        </div>

        {filteredBuiltin.length === 0 ? (
          <div className="flex items-center justify-center py-10">
            <p className="text-[13px] text-fg-4">No tools match your search.</p>
          </div>
        ) : (
          <div>
            {filteredBuiltin.map(tool => (
              <BuiltinToolRow
                key={tool.id}
                tool={tool}
                hidden={hiddenToolIds.has(tool.id)}
                onToggle={() => onToggleHidden(tool.id)}
              />
            ))}
          </div>
        )}
      </div>

    </div>
  );
}
