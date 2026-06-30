import { useState, useMemo } from 'react';
import type { Tool, SubmissionRisk, RequiresAccount } from '../types/tool';
import type { IocType } from '../types/ioc';

interface Props {
  builtinTools: Tool[];
  customTools: Tool[];
  hiddenToolIds: Set<string>;
  saving: boolean;
  onSaveCustomTools: (tools: Tool[]) => Promise<void>;
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

const ALL_WORKFLOWS: { id: string; name: string }[] = [
  { id: 'ip-triage',            name: 'IP Triage' },
  { id: 'domain-triage',        name: 'Domain Triage' },
  { id: 'url-phishing',         name: 'URL / Phishing' },
  { id: 'spam-source',          name: 'Spam Source' },
  { id: 'malware-hash',         name: 'Malware / Hash' },
  { id: 'suspicious-connection',name: 'Suspicious Connection' },
  { id: 'waf-web-attack',       name: 'WAF / Web Attack' },
  { id: 'dark-web-exposure',    name: 'Dark Web / Credential' },
  { id: 'takedown-reporting',   name: 'Takedown Reporting' },
  { id: 'ransomware-context',   name: 'Ransomware Context' },
  { id: 'external-exposure',    name: 'External Exposure' },
  { id: 'cve-context',          name: 'CVE Context' },
  { id: 'email-header-review',  name: 'Email Header Review' },
  { id: 'business-domain-osint',name: 'Business Domain Profile' },
];

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

// ── Form state ────────────────────────────────────────────────────────────────

interface FormState {
  name: string;
  category: string;
  description: string;
  urlTemplate: string;
  inputTypes: IocType[];
  workflows: string[];
  whyUse: string;
  lookFor: string;
  riskNote: string;
  submissionRisk: SubmissionRisk;
  requiresAccount: RequiresAccount;
  tags: string;
}

const DEFAULT_FORM: FormState = {
  name: '',
  category: 'Custom',
  description: '',
  urlTemplate: '',
  inputTypes: [],
  workflows: [],
  whyUse: '',
  lookFor: '',
  riskNote: '',
  submissionRisk: 'low',
  requiresAccount: 'none',
  tags: '',
};

function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function generateId(name: string, taken: Set<string>): string {
  const base = 'custom-' + slugify(name);
  let id = base;
  let n = 2;
  while (taken.has(id)) id = `${base}-${n++}`;
  return id;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Checkbox({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="inline-flex items-center gap-1.5 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
        className="w-3.5 h-3.5 rounded border-[#d0d5dd] text-[#1570ef] focus:ring-[#1570ef]/20"
      />
      <span className="text-[12px] text-[#344054]">{label}</span>
    </label>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return <p className="text-[11px] font-semibold text-[#344054] uppercase tracking-wide mb-1.5">{children}</p>;
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
        className={`w-full text-[13px] px-3 py-2 border rounded-lg bg-white text-[#101828] placeholder-[#98a2b3] focus:outline-none focus:ring-2 transition-colors ${
          error ? 'border-[#fecdca] focus:border-[#d92d20] focus:ring-[#d92d20]/10' : 'border-[#d0d5dd] focus:border-[#1570ef] focus:ring-[#1570ef]/10'
        }`}
      />
      {error && <p className="text-[11px] text-[#d92d20] mt-1">{error}</p>}
    </div>
  );
}

function CategoryBadge({ category }: { category: string }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#f2f4f7] border border-[#e4e7ec] text-[#475467]">
      {category}
    </span>
  );
}

// ── Custom tool row ───────────────────────────────────────────────────────────

function CustomToolRow({ tool, onDelete }: { tool: Tool; onDelete: () => void }) {
  return (
    <div className="flex items-start gap-3 p-4 border border-[#e4e7ec] rounded-xl bg-white">
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-1">
          <span className="text-[13px] font-semibold text-[#101828]">{tool.name}</span>
          <CategoryBadge category={tool.category} />
        </div>
        <p className="text-[11px] font-mono text-[#667085] truncate mb-2">{tool.urlTemplate}</p>
        <div className="flex flex-wrap gap-1.5">
          {tool.inputTypes.map(t => (
            <span key={t} className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-[#eff8ff] border border-[#b2ddff] text-[#175cd3]">
              {t.toUpperCase()}
            </span>
          ))}
          {tool.workflows.map(w => {
            const wf = ALL_WORKFLOWS.find(x => x.id === w);
            return wf ? (
              <span key={w} className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-[#f9fafb] border border-[#e4e7ec] text-[#667085]">
                {wf.name}
              </span>
            ) : null;
          })}
        </div>
      </div>
      <button
        onClick={onDelete}
        className="shrink-0 text-xs font-medium px-3 py-1.5 rounded-lg border border-[#fecdca] bg-[#fef3f2] text-[#b42318] hover:bg-[#fee4e2] transition-colors"
      >
        Delete
      </button>
    </div>
  );
}

// ── Built-in tool row ─────────────────────────────────────────────────────────

function BuiltinToolRow({ tool, hidden, onToggle }: { tool: Tool; hidden: boolean; onToggle: () => void }) {
  return (
    <div className={`flex items-start gap-3 px-4 py-3 border-b border-[#f2f4f7] last:border-0 transition-opacity ${hidden ? 'opacity-50' : ''}`}>
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-0.5">
          <span className="text-[13px] font-semibold text-[#101828]">{tool.name}</span>
          <CategoryBadge category={tool.category} />
        </div>
        <p className="text-[12px] text-[#667085] truncate">{tool.description}</p>
      </div>
      <button
        onClick={onToggle}
        className={`shrink-0 inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-full border transition-colors ${
          hidden
            ? 'bg-[#f2f4f7] border-[#e4e7ec] text-[#98a2b3] hover:border-[#d0d5dd] hover:text-[#667085]'
            : 'bg-[#ecfdf3] border-[#abefc6] text-[#067647] hover:bg-[#d1fadf]'
        }`}
      >
        <span className={`w-1.5 h-1.5 rounded-full ${hidden ? 'bg-[#98a2b3]' : 'bg-[#079455]'}`} />
        {hidden ? 'Hidden' : 'Visible'}
      </button>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export function ToolsManagementPanel({ builtinTools, customTools, hiddenToolIds, saving, onSaveCustomTools, onToggleHidden }: Props) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(DEFAULT_FORM);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [showOptional, setShowOptional] = useState(false);
  const [search, setSearch] = useState('');
  const [showHiddenOnly, setShowHiddenOnly] = useState(false);
  const [showVarRef, setShowVarRef] = useState(false);

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

  function patchForm(patch: Partial<FormState>) {
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
    const e: Record<string, string> = {};
    if (!form.name.trim()) e.name = 'Name is required.';
    if (!form.urlTemplate.trim()) e.urlTemplate = 'URL template is required.';
    else if (!/^https?:\/\//i.test(form.urlTemplate.trim())) e.urlTemplate = 'Must start with https:// or http://';
    if (form.inputTypes.length === 0) e.inputTypes = 'Select at least one IOC type.';
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function handleSave() {
    if (!validate()) return;
    const allIds = new Set([...builtinTools.map(t => t.id), ...customTools.map(t => t.id)]);
    const newTool: Tool = {
      id: generateId(form.name.trim(), allIds),
      name: form.name.trim(),
      category: form.category,
      description: form.description.trim(),
      urlTemplate: form.urlTemplate.trim(),
      inputTypes: form.inputTypes,
      workflows: form.workflows,
      whyUse: form.whyUse.trim(),
      lookFor: form.lookFor.trim(),
      riskNote: form.riskNote.trim() || 'This is a custom tool.',
      submissionRisk: form.submissionRisk,
      requiresAccount: form.requiresAccount,
      tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
    };
    await onSaveCustomTools([...customTools, newTool]);
    setForm(DEFAULT_FORM);
    setErrors({});
    setShowForm(false);
    setShowOptional(false);
  }

  function handleCancel() {
    setForm(DEFAULT_FORM);
    setErrors({});
    setShowForm(false);
    setShowOptional(false);
  }

  async function handleDelete(id: string) {
    await onSaveCustomTools(customTools.filter(t => t.id !== id));
  }

  return (
    <div className="space-y-4">

      {/* ── Custom tools ─────────────────────────────────────────────────── */}
      <div className="wb-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="wb-label">Custom Tools</p>
            {customTools.length > 0 && (
              <p className="text-[12px] text-[#98a2b3] mt-0.5">{customTools.length} custom tool{customTools.length !== 1 ? 's' : ''} added</p>
            )}
          </div>
          {!showForm && (
            <button
              onClick={() => setShowForm(true)}
              className="inline-flex items-center gap-1.5 text-[13px] font-semibold px-3.5 py-2 rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] transition-colors"
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
          <div className="border border-[#e4e7ec] rounded-xl p-5 bg-[#fafbfc] mb-4 space-y-4">
            <p className="text-[13px] font-semibold text-[#101828]">New Custom Tool</p>

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
                  className="w-full text-[13px] px-3 py-2 border border-[#d0d5dd] rounded-lg bg-white text-[#101828] focus:outline-none focus:border-[#1570ef] focus:ring-2 focus:ring-[#1570ef]/10"
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
                  className="text-[11px] text-[#1570ef] hover:underline"
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
                <div className="mt-2 p-3 rounded-lg border border-[#e4e7ec] bg-white">
                  <p className="text-[11px] font-semibold text-[#667085] uppercase tracking-wide mb-2">Available variables</p>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1">
                    {TEMPLATE_VARS.map(({ v, desc }) => (
                      <div key={v} className="flex items-baseline gap-2">
                        <code className="text-[11px] font-mono text-[#175cd3] shrink-0">{v}</code>
                        <span className="text-[11px] text-[#98a2b3]">{desc}</span>
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
              {errors.inputTypes && <p className="text-[11px] text-[#d92d20] mt-1">{errors.inputTypes}</p>}
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
              className="text-[12px] text-[#667085] hover:text-[#344054] flex items-center gap-1.5 transition-colors"
            >
              <svg className={`w-3.5 h-3.5 transition-transform ${showOptional ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 18l6-6-6-6" />
              </svg>
              {showOptional ? 'Hide' : 'Show'} optional fields (description, why use, risk note…)
            </button>

            {showOptional && (
              <div className="space-y-3 pt-1 border-t border-[#f2f4f7]">
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
                      className="w-full text-[13px] px-3 py-2 border border-[#d0d5dd] rounded-lg bg-white text-[#101828] focus:outline-none focus:border-[#1570ef]"
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
                      className="w-full text-[13px] px-3 py-2 border border-[#d0d5dd] rounded-lg bg-white text-[#101828] focus:outline-none focus:border-[#1570ef]"
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
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#f2f4f7]">
              <button
                onClick={handleCancel}
                className="text-[13px] font-medium px-4 py-2 rounded-lg border border-[#e4e7ec] bg-white text-[#475467] hover:border-[#d0d5dd] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => { void handleSave(); }}
                disabled={saving}
                className="text-[13px] font-semibold px-4 py-2 rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] disabled:opacity-60 transition-colors"
              >
                {saving ? 'Saving…' : 'Save Tool'}
              </button>
            </div>
          </div>
        )}

        {/* Custom tool list */}
        {customTools.length === 0 ? (
          <div className={`flex items-center justify-center py-10 ${showForm ? 'hidden' : ''}`}>
            <div className="text-center space-y-2">
              <div className="w-10 h-10 rounded-xl bg-[#f2f4f7] flex items-center justify-center mx-auto">
                <svg className="w-5 h-5 text-[#98a2b3]" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
                </svg>
              </div>
              <p className="text-[13px] text-[#667085]">No custom tools yet.</p>
              <p className="text-[12px] text-[#98a2b3]">Click "Add Custom Tool" to add your own investigation links.</p>
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
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#f2f4f7]">
          <div>
            <p className="wb-label">Built-in Tools</p>
            <p className="text-[12px] text-[#98a2b3] mt-0.5">
              {builtinTools.length} tools
              {hiddenCount > 0 && <> · <span className="text-[#b54708]">{hiddenCount} hidden</span></>}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {hiddenCount > 0 && (
              <button
                onClick={() => setShowHiddenOnly(v => !v)}
                className={`text-[12px] font-medium px-3 py-1.5 rounded-lg border transition-colors ${
                  showHiddenOnly
                    ? 'border-[#fedf89] bg-[#fffaeb] text-[#b54708]'
                    : 'border-[#e4e7ec] bg-white text-[#667085] hover:border-[#d0d5dd]'
                }`}
              >
                {showHiddenOnly ? 'Show all' : `Show ${hiddenCount} hidden`}
              </button>
            )}
            <div className="relative">
              <svg className="w-4 h-4 text-[#98a2b3] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
                <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" />
              </svg>
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search tools…"
                className="pl-9 pr-3 py-1.5 text-[13px] border border-[#e4e7ec] rounded-lg bg-white text-[#101828] placeholder-[#98a2b3] focus:outline-none focus:border-[#1570ef] focus:ring-2 focus:ring-[#1570ef]/10 w-52 transition-colors"
              />
            </div>
          </div>
        </div>

        {filteredBuiltin.length === 0 ? (
          <div className="flex items-center justify-center py-10">
            <p className="text-[13px] text-[#98a2b3]">No tools match your search.</p>
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
