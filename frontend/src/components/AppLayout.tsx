import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { Menu, X, LogOut, LayoutDashboard, HardDrive, Smartphone, ShieldAlert, Users, FileText, Search, FolderSearch, Radar, Lock } from "lucide-react";
import { Brand } from "./Brand";
import { useAuth } from "../lib/auth";
import { tokenStore } from "../lib/api";
import { isVulnModuleEnabled } from "../lib/vulnFlags";
import { isForensicService, isUnifiedService, isDedicatedMobileService, mobilePlatformService, serviceProductTitle } from "../lib/serviceMode";

type NavEntry = { to: string; label: string; icon: typeof LayoutDashboard; perm?: string; platform?: boolean };
function navigation(): NavEntry[] {
  const mobileBase = isDedicatedMobileService() ? `/mobile/${mobilePlatformService() || "android"}` : "/mobile";
  const links: NavEntry[] = [
    { to: "/", label: "Dashboard", icon: LayoutDashboard },
    { to: "/users", label: "Users", icon: Users, perm: "user:read" },
    { to: "/roles", label: "Roles", icon: Lock, perm: "role:read" },
  ];
  if (isForensicService()) links.push(
    { to: "/forensic/jobs", label: "Disk Jobs", icon: HardDrive, perm: "job:read" },
    { to: "/forensic/artifacts", label: "Disk Artifacts", icon: FolderSearch, perm: "artifact:read" },
    { to: "/forensic/reports", label: "Disk Reports", icon: FileText, perm: "job:read" },
  );
  if (isUnifiedService() || isDedicatedMobileService()) links.push(
    { to: mobileBase, label: "Mobile Jobs", icon: Smartphone, perm: "job:read" },
    { to: `${mobileBase}/artifacts`, label: "Mobile Artifacts", icon: FolderSearch, perm: "artifact:read" },
    { to: `${mobileBase}/rag`, label: "Mobile RAG", icon: Search, perm: "job:read" },
    { to: `${mobileBase}/reports`, label: "Mobile Reports", icon: FileText, perm: "job:read" },
  );
  if (isVulnModuleEnabled()) links.push(
    { to: "/vuln/dashboards", label: "Vulnerability Dashboard", icon: ShieldAlert, perm: "vuln:read" },
    { to: "/vuln/scans", label: "Vulnerability Scans", icon: Radar, perm: "scan:read" },
    { to: "/vuln/findings", label: "Findings", icon: ShieldAlert, perm: "vuln:read" },
  );
  return links;
}

export function AppLayout() {
  const { user, logout, hasPermission, isPlatformScope } = useAuth();
  const { pathname } = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const links = navigation().filter((entry) => (!entry.perm || hasPermission(entry.perm)) && (!entry.platform || isPlatformScope));
  const sidebar = <>
    <div className="p-4"><Brand /></div>
    <nav className="flex-1 overflow-y-auto px-3 pb-6" aria-label="Main navigation">
      {links.map((entry) => <NavLink key={entry.to} to={entry.to} end={entry.to === "/"} onClick={() => setMobileOpen(false)} className={({isActive}) => `mb-1 flex items-center gap-3 rounded-lg px-3 py-2 text-sm ${isActive ? "bg-brand-50 font-semibold text-brand-900" : "text-ink-600 hover:bg-brand-50"}`}>
        <entry.icon className="h-4 w-4 shrink-0" /><span>{entry.label}</span>
      </NavLink>)}
    </nav>
  </>;
  const current = links.find((link) => link.to === pathname)?.label || serviceProductTitle();
  return <div className="min-h-screen bg-transparent">
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-56 flex-col border-r border-ink-300 bg-white lg:flex">{sidebar}</aside>
    {mobileOpen && <div className="fixed inset-0 z-50 lg:hidden"><button type="button" aria-label="Close menu" className="absolute inset-0 w-full bg-black/40" onClick={() => setMobileOpen(false)} /><aside className="absolute inset-y-0 left-0 flex w-64 flex-col bg-white"><button type="button" aria-label="Close navigation" className="self-end p-3" onClick={() => setMobileOpen(false)}><X className="h-5 w-5" /></button>{sidebar}</aside></div>}
    <div className="lg:pl-56">
      <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-ink-300 bg-white px-4 shadow-sm sm:px-8">
        <div className="flex items-center gap-3"><button type="button" aria-label="Open navigation" className="p-2 lg:hidden" onClick={() => setMobileOpen(true)}><Menu className="h-5 w-5" /></button><div><p className="text-xs text-brand-600">{serviceProductTitle()}</p><h1 className="font-semibold text-ink-900">{current}</h1></div></div>
        <div className="flex items-center gap-3"><div className="hidden text-right text-sm sm:block"><p>{user?.email}</p><p className="text-xs text-ink-400">Tenant: {tokenStore.tenant()}</p></div><button type="button" onClick={logout} className="flex items-center gap-1 rounded-lg border border-ink-300 px-3 py-2 text-sm"><LogOut className="h-4 w-4" />Logout</button></div>
      </header>
      <main className="container-fluid mx-auto max-w-7xl px-4 py-6 sm:px-8"><Outlet /></main>
    </div>
  </div>;
}
