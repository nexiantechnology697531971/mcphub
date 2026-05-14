"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { readPlatformSession, type PlatformSession } from "../lib/platform-auth";
import { fetchAuditEvents, type PlatformAuditEvent } from "../lib/platform-api";

export function AuditPanel() {
  const router = useRouter();
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [events, setEvents] = useState<PlatformAuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    const stored = readPlatformSession();
    if (!stored) {
      router.replace("/auth/login");
      return;
    }
    setSession(stored);
  }, [router]);

  useEffect(() => {
    async function load() {
      if (!session) return;
      setLoading(true);
      setNotice("");
      try {
        const payload = await fetchAuditEvents({ tenantId: session.tenant.id, limit: 25 }, session);
        setEvents(payload.events);
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Could not load audit activity.");
      } finally {
        setLoading(false);
      }
    }

    void load();
  }, [session]);

  return (
    <div className="stack">
      {notice ? <div className="notice">{notice}</div> : null}

      {!loading && events.length ? (
        <section className="panel stack">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Recent Activity</span>
              <h2>Latest workspace events</h2>
            </div>
          </div>
          <div className="timeline">
            {events.slice(0, 8).map((event) => (
              <div key={event.id} className="timeline-item">
                <span className="timeline-time">
                  {new Date(event.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </span>
                <div>
                  <strong>{event.action}</strong>
                  <p className="muted">
                    {event.targetType}
                    {event.targetId ? ` · ${event.targetId}` : ""}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      <div className="data-table-wrapper">
        {loading ? (
          <div className="panel">Loading audit activity...</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Target</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td>{new Date(event.createdAt).toLocaleString()}</td>
                  <td><span className="chip">{event.action}</span></td>
                  <td>{event.targetType}{event.targetId ? ` · ${event.targetId}` : ""}</td>
                  <td>{JSON.stringify(event.metadata)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
