import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, Plus, Shield } from "lucide-react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import { useAuth } from "../../lib/auth";
import type { ScanPolicy, ScanPolicyTemplate, Scanner } from "../../lib/types/vuln";

const CATEGORY_LABEL: Record<string, string> = {
  discovery: "Discovery",
  vulnerability: "Vulnerability scans",
  compliance: "Compliance",
  threat: "Threat checks",
};

const PORT_PROFILE_LABEL: Record<string, string> = {
  nessus: "Nessus default ports (IANA TCP list + service ports)",
  nexus: "Nessus default ports (IANA TCP list + service ports)",
  full: "All 65,535 TCP ports",
  catalog: "Service catalog ports",
  focused: "Only the listed ports",
};

const UDP_LABEL: Record<string, string> = {
  priority: "30 common UDP service ports",
  off: "No UDP",
  full: "All 65,535 UDP ports (slow)",
};

function portScope(settings: Record<string, unknown> | null | undefined): string {
  const profile = String(settings?.port_profile ?? "");
  const custom = Array.isArray(settings?.custom_tcp_ports) ? (settings?.custom_tcp_ports as unknown[]) : [];
  if (profile === "focused" && custom.length) return `TCP ${custom.join(", ")}`;
  const base = PORT_PROFILE_LABEL[profile] || (profile ? profile : "Scanner default");
  return custom.length ? `${base} + ${custom.length} extra` : base;
}

function parsePorts(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
}

export function ScanPoliciesPage() {
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canManage = hasPermission("scan:policy_manage");

  const [policies, setPolicies] = useState<ScanPolicy[]>([]);
  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [templates, setTemplates] = useState<ScanPolicyTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [p, s, t] = await Promise.all([
        vulnApi.listScanPolicies(),
        vulnApi.listScanners(),
        vulnApi.listScanPolicyTemplates().catch(() => [] as ScanPolicyTemplate[]),
      ]);
      setPolicies(p);
      setScanners(s);
      setTemplates(t);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const templateByKey = useMemo(() => new Map(templates.map((t) => [t.key, t])), [templates]);

  return (
    <div>
      <PageHeader
        title="Scan policies"
        subtitle="Reusable scan settings. Start from a Nessus-equivalent template, then adjust ports, UDP, and credentials."
        actions={
          canManage && (
            <Button variant="brand" onClick={() => setCreateOpen(true)} disabled={templates.length === 0 && !loading}>
              <Plus className="h-4 w-4" /> New policy
            </Button>
          )
        }
      />

      <Card className="overflow-hidden">
        {loading ? (
          <Spinner />
        ) : policies.length === 0 ? (
          <p className="px-5 py-16 text-center text-sm text-ink-400">
            No scan policies yet. Create one from a template to control ports, UDP, and credentials for your scans.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Policy</th>
                  <th className="px-5 py-3 font-semibold">Template</th>
                  <th className="px-5 py-3 font-semibold">Ports</th>
                  <th className="px-5 py-3 font-semibold">Credentials</th>
                  <th className="px-5 py-3 font-semibold">Framework</th>
                  <th className="px-5 py-3 font-semibold">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {policies.map((p) => {
                  const settings = (p.settings_json || {}) as Record<string, unknown>;
                  const template = p.template_key ? templateByKey.get(p.template_key) : undefined;
                  const effective = { ...(template?.settings || {}), ...settings };
                  const refs = (settings.gmp_credential_refs || {}) as Record<string, string>;
                  const credKinds = Object.keys(refs);
                  return (
                    <tr key={p.id} className="hover:bg-ink-50/60">
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-3">
                          <Shield className="h-4 w-4 text-brand-600" />
                          <span className="font-semibold text-ink-800">{p.name}</span>
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        {template ? (
                          <div>
                            <span className="text-ink-800">{template.name}</span>
                            <span className="block text-xs text-ink-500">Nessus: {template.nessus_template}</span>
                          </div>
                        ) : (
                          <Badge tone="neutral">{p.policy_type}</Badge>
                        )}
                      </td>
                      <td className="px-5 py-3 text-ink-600">
                        {portScope(effective)}
                        <span className="block text-xs text-ink-500">
                          {UDP_LABEL[String(effective.udp_profile ?? "")] || "Scanner default UDP"}
                          {effective.performance ? ` · ${String(effective.performance) === "fast" ? "Fast" : "Standard"} speed` : ""}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-ink-600">
                        {credKinds.length ? (
                          <span className="inline-flex items-center gap-1">
                            <KeyRound className="h-3.5 w-3.5" /> {credKinds.map((k) => k.toUpperCase()).join(", ")}
                          </span>
                        ) : template?.requires_credentials.length ? (
                          <span className="text-red-700">Missing (required)</span>
                        ) : (
                          "None"
                        )}
                      </td>
                      <td className="px-5 py-3 text-ink-500">{p.compliance_framework || "—"}</td>
                      <td className="px-5 py-3 text-ink-500">{new Date(p.created_at).toLocaleDateString()}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {createOpen && (
        <PolicyModal
          scanners={scanners}
          templates={templates}
          onClose={() => setCreateOpen(false)}
          onSaved={() => {
            setCreateOpen(false);
            load();
          }}
        />
      )}
    </div>
  );
}

function PolicyModal({
  scanners,
  templates,
  onClose,
  onSaved,
}: {
  scanners: Scanner[];
  templates: ScanPolicyTemplate[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const initial = templates.find((t) => t.key === "basic_network") || templates[0];
  const [templateKey, setTemplateKey] = useState(initial?.key || "");
  const template = templates.find((t) => t.key === templateKey);
  const [name, setName] = useState(initial?.name || "");
  const [nameTouched, setNameTouched] = useState(false);
  const [scannerId, setScannerId] = useState("");
  const [portProfile, setPortProfile] = useState("");
  const [udpProfile, setUdpProfile] = useState("");
  const [performance, setPerformance] = useState("");
  const [extraPorts, setExtraPorts] = useState("");
  const [smbRef, setSmbRef] = useState("");
  const [sshRef, setSshRef] = useState("");
  const [framework, setFramework] = useState(initial?.compliance_framework || "");

  const grouped = useMemo(() => {
    const out = new Map<string, ScanPolicyTemplate[]>();
    for (const t of templates) out.set(t.category, [...(out.get(t.category) || []), t]);
    return out;
  }, [templates]);

  function chooseTemplate(key: string) {
    const next = templates.find((t) => t.key === key);
    setTemplateKey(key);
    if (next && !nameTouched) setName(next.name);
    setFramework(next?.compliance_framework || "");
    setPortProfile("");
    setUdpProfile("");
  }

  const required = template?.requires_credentials || [];
  const credentialsMissing = required.length > 0 && !smbRef.trim() && !sshRef.trim();
  const focused = template?.settings.port_profile === "focused";

  async function submit() {
    if (!template) return;
    const settings: Record<string, unknown> = {};
    if (portProfile) settings.port_profile = portProfile;
    if (udpProfile) settings.udp_profile = udpProfile;
    if (performance) settings.performance = performance;
    const extra = parsePorts(extraPorts);
    if (extra.length) {
      const base = (template.settings.custom_tcp_ports || []).map(String);
      settings.custom_tcp_ports = Array.from(new Set([...base, ...extra]));
    }
    const refs: Record<string, string> = {};
    if (smbRef.trim()) refs.smb = smbRef.trim();
    if (sshRef.trim()) refs.ssh = sshRef.trim();
    if (Object.keys(refs).length) settings.gmp_credential_refs = refs;
    setLoading(true);
    try {
      await vulnApi.createScanPolicy({
        name: name.trim() || template.name,
        policy_type: template.category,
        scanner_id: scannerId || null,
        compliance_framework: framework || null,
        template_key: template.key,
        settings_json: settings,
      });
      toast.success("Policy created");
      onSaved();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Create failed");
    } finally {
      setLoading(false);
    }
  }

  const s = template?.settings || {};
  const effectivePorts = portScope({ ...s, ...(portProfile ? { port_profile: portProfile } : {}) });
  const effectiveUdp = UDP_LABEL[udpProfile || String(s.udp_profile ?? "")] || "Scanner default UDP";

  return (
    <Modal
      open
      onClose={onClose}
      title="New scan policy"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit} disabled={!template || credentialsMissing}>
            Create policy
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Template">
          <Select value={templateKey} onChange={(e) => chooseTemplate(e.target.value)}>
            {Array.from(grouped.entries()).map(([category, items]) => (
              <optgroup key={category} label={CATEGORY_LABEL[category] || category}>
                {items.map((t) => (
                  <option key={t.key} value={t.key}>
                    {t.name}
                  </option>
                ))}
              </optgroup>
            ))}
          </Select>
        </Field>

        {template ? (
          <div className="rounded-xl border border-ink-200 bg-white px-4 py-3 text-sm">
            <p className="text-ink-700">{template.description}</p>
            <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-ink-600">
              <dt className="font-semibold text-ink-700">Nessus equivalent</dt>
              <dd>{template.nessus_template}</dd>
              <dt className="font-semibold text-ink-700">TCP ports</dt>
              <dd>{effectivePorts}</dd>
              <dt className="font-semibold text-ink-700">UDP</dt>
              <dd>{effectiveUdp}</dd>
              <dt className="font-semibold text-ink-700">Greenbone config</dt>
              <dd>{String(s.scan_config || "Full and fast")}</dd>
              <dt className="font-semibold text-ink-700">Safe checks</dt>
              <dd>{s.safe_checks === "no" ? "Off (may disrupt services)" : "On"}</dd>
              <dt className="font-semibold text-ink-700">Checks run</dt>
              <dd>
                {s.optimize_test === "no"
                  ? "Every check, even for services not detected (slower)"
                  : "Only checks for services the scan detects (Nessus default)"}
              </dd>
              {s.nvt_families?.length ? (
                <>
                  <dt className="font-semibold text-ink-700">Check families</dt>
                  <dd>{s.nvt_families.join(", ")}</dd>
                </>
              ) : null}
              {s.cve_watchlist?.length ? (
                <>
                  <dt className="font-semibold text-ink-700">CVE watchlist</dt>
                  <dd className="break-words">{s.cve_watchlist.join(", ")}</dd>
                </>
              ) : null}
            </dl>
            <details className="mt-3">
              <summary className="cursor-pointer text-xs font-semibold text-brand-700">How this differs from Nessus</summary>
              <p className="mt-1 text-xs text-ink-600">{template.deviations}</p>
            </details>
          </div>
        ) : (
          <p className="text-sm text-red-700">Templates could not be loaded. Check that the server is on Polaron 1.6.5.</p>
        )}

        <Field label="Name">
          <Input
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setNameTouched(true);
            }}
          />
        </Field>

        <Field label="Scanner" hint="Optional. Jobs can still pick a scanner when they are launched.">
          <Select value={scannerId} onChange={(e) => setScannerId(e.target.value)}>
            <option value="">Choose at launch</option>
            {scanners.map((sc) => (
              <option key={sc.id} value={sc.id}>
                {sc.name}
              </option>
            ))}
          </Select>
        </Field>

        {!focused ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="TCP port scope">
              <Select value={portProfile} onChange={(e) => setPortProfile(e.target.value)}>
                <option value="">Template default</option>
                <option value="nessus">Nessus default ports</option>
                <option value="full">All 65,535 TCP ports</option>
                <option value="catalog">Service catalog ports</option>
              </Select>
            </Field>
            <Field label="UDP">
              <Select value={udpProfile} onChange={(e) => setUdpProfile(e.target.value)}>
                <option value="">Template default</option>
                <option value="priority">30 common UDP service ports</option>
                <option value="off">No UDP</option>
                <option value="full">All UDP ports (slow)</option>
              </Select>
            </Field>
          </div>
        ) : null}

        <Field
          label="Speed"
          hint={
            performance === "standard"
              ? "Pre-1.6.6 timing: 10 s socket timeout, 4 checks per host, every check gets its full 320 s."
              : "Fast keeps every check and port. It uses the Nessus/OpenVAS default 5 s socket timeout, 5 checks per host, Nmap Aggressive timing, and shorter time limits only for checks that already timed out repeatedly."
          }
        >
          <Select value={performance} onChange={(e) => setPerformance(e.target.value)}>
            <option value="">Scanner default</option>
            <option value="fast">Fast</option>
            <option value="standard">Standard</option>
          </Select>
        </Field>

        <Field
          label={focused ? "Extra TCP ports" : "Additional TCP ports"}
          hint="Comma-separated ports or ranges, for example 8888, 9443, 10000-10010."
        >
          <Input value={extraPorts} onChange={(e) => setExtraPorts(e.target.value)} placeholder="8888, 9443" />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label={required.includes("smb") ? "SMB credential ID (Windows)" : "SMB credential ID (optional)"}
            hint="Greenbone credential UUID on the laptop scanner."
          >
            <Input value={smbRef} onChange={(e) => setSmbRef(e.target.value)} placeholder="UUID" />
          </Field>
          <Field
            label={required.includes("ssh") ? "SSH credential ID (Linux/macOS)" : "SSH credential ID (optional)"}
            error={credentialsMissing ? `${template?.name} needs an SMB or SSH credential ID.` : undefined}
          >
            <Input value={sshRef} onChange={(e) => setSshRef(e.target.value)} placeholder="UUID" />
          </Field>
        </div>

        <Field label="Compliance framework" hint="Optional label for reports, for example PCI DSS.">
          <Input value={framework} onChange={(e) => setFramework(e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}
