"use client";

import Link from "next/link";
import type { Route } from "next";
import { usePathname } from "next/navigation";

import { NexianLogo } from "./nexian-logo";
import { clearPlatformSession, hasPlatformConsoleAccess, readPlatformSession } from "../lib/platform-auth";

const adminNav = [
  {
    section: "Core",
    items: [
      { href: "/admin/dashboard", label: "Overview", caption: "Platform health" },
      { href: "/admin/tenants", label: "Tenants", caption: "Customer estates" },
      { href: "/admin/users", label: "Users", caption: "Platform access" }
    ]
  },
  {
    section: "Operations",
    items: [
      { href: "/admin/connectors", label: "Connectors", caption: "Provider health" },
      { href: "/admin/modules", label: "Modules", caption: "Group apps and tools" },
      { href: "/admin/audit", label: "Audit", caption: "Cross-tenant activity" }
    ]
  },
  {
    section: "Admin",
    items: [
      { href: "/admin/settings", label: "Settings", caption: "Commercial and security defaults" }
    ]
  }
] as const;

const tenantNav = [
  {
    section: "",
    items: [
      { href: "/dashboard", label: "Overview", caption: "Workspace health" },
      { href: "/dashboard/connectors", label: "Connectors", caption: "Linked products" },
      { href: "/dashboard/chat", label: "Chat", caption: "Talk to the Nexian agent" },
      { href: "/dashboard/workflows", label: "Automation", caption: "Workflows and executions" },
      { href: "/dashboard/settings", label: "Settings", caption: "Permissions, audit, MCP, agent" }
    ]
  }
] as const;

function getInitials(name: string) {
  return name
    .split(" ")
    .map((part) => part[0] ?? "")
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

export function Sidebar({ variant }: { variant: "admin" | "tenant" }) {
  const pathname = usePathname();
  const session = readPlatformSession();
  const navGroups = variant === "admin" ? adminNav : tenantNav;
  const displayName = session?.user.displayName ?? "Guest";
  const roleLabel =
    variant === "admin"
      ? session?.user.platformRole ?? "No platform role"
      : session?.user.tenantRole ?? session?.user.role ?? "No tenant role";

  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <Link href={(variant === "admin" ? "/admin/dashboard" : "/dashboard") as Route} className="sidebar-brand">
          <span className="sidebar-logo">
            <NexianLogo className="sidebar-logo-image" priority="high" />
          </span>
          <span className="sidebar-brand-copy">
            <strong>Nexian Command Platform</strong>
            <span>{variant === "admin" ? "MSP Operations Console" : "Customer Workspace"}</span>
          </span>
        </Link>

        <nav className="sidebar-nav">
          {navGroups.map((group) => (
            <div key={group.section || "primary"} className="sidebar-group">
              {group.section ? <span className="sidebar-group-title">{group.section}</span> : null}
              {group.items.map((item) => {
                const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
                return (
                  <Link key={item.href} href={item.href as Route} className={`sidebar-link ${active ? "active" : ""}`}>
                    <span className="sidebar-link-label">{item.label}</span>
                    <span className="sidebar-link-caption">{item.caption}</span>
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
      </div>

      <div className="sidebar-user">
        <div className="sidebar-avatar">{getInitials(displayName)}</div>
        <div className="sidebar-user-copy">
          <strong>{displayName}</strong>
          <span>{session?.user.email ?? "No active session"}</span>
          <span>{variant === "admin" && !hasPlatformConsoleAccess(session) ? "Tenant-only access" : roleLabel}</span>
        </div>
        <button
          className="button secondary sidebar-signout"
          type="button"
          onClick={() => {
            clearPlatformSession();
            window.location.href = "/auth/login";
          }}
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}
