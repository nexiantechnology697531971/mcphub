"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import { readPlatformSession, type PlatformSession } from "../lib/platform-auth";

type ChatMessage = {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
};

export function AgentChat() {
  const router = useRouter();
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);

  const apiOrigin = useMemo(() => {
    if (typeof window === "undefined") {
      return process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
    }
    return process.env.NEXT_PUBLIC_API_URL ?? window.location.origin.replace(":3000", ":4000");
  }, []);

  useEffect(() => {
    const stored = readPlatformSession();
    if (!stored) {
      router.replace("/auth/login");
      return;
    }
    setSession(stored);
  }, [router]);

  async function send() {
    const trimmed = input.trim();
    if (!trimmed || sending || !session) {
      return;
    }

    const userMessage: ChatMessage = {
      id: `${Date.now()}-u-${Math.random().toString(36).slice(2, 6)}`,
      role: "user",
      content: trimmed
    };
    setMessages((current) => [...current, userMessage]);
    setInput("");
    setSending(true);

    try {
      const response = await fetch(`${apiOrigin}/connectors/actionstep/chat`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({
          message: trimmed,
          history: messages.map(({ role, content }) => ({ role, content }))
        })
      });

      const payload = (await response.json()) as { reply?: string; error?: string; message?: string };
      if (!response.ok) {
        throw new Error(payload.message ?? payload.error ?? "Chat request failed.");
      }

      const reply = payload.reply?.trim();
      setMessages((current) => [
        ...current,
        {
          id: `${Date.now()}-a-${Math.random().toString(36).slice(2, 6)}`,
          role: "assistant",
          content: reply && reply.length > 0 ? reply : "(no response)"
        }
      ]);
    } catch (error) {
      setMessages((current) => [
        ...current,
        {
          id: `${Date.now()}-s-${Math.random().toString(36).slice(2, 6)}`,
          role: "system",
          content: error instanceof Error ? error.message : "Could not reach the agent."
        }
      ]);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="chat-shell">
      <div className="chat-log">
        {messages.length === 0 ? (
          <div className="chat-empty">
            Ask the Nexian agent about a matter, ticket, contact, workflow, or any tool the platform exposes.
          </div>
        ) : (
          messages.map((message) => (
            <div key={message.id} className={`chat-message ${message.role}`}>
              {message.content}
            </div>
          ))
        )}
        {sending ? <div className="chat-message system">Thinking…</div> : null}
      </div>
      <div className="chat-composer">
        <textarea
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              void send();
            }
          }}
          placeholder="Ask the agent…"
          disabled={sending}
        />
        <button
          className="button primary"
          onClick={() => void send()}
          type="button"
          disabled={sending || !input.trim()}
        >
          {sending ? "Sending…" : "Send"}
        </button>
      </div>
    </div>
  );
}
