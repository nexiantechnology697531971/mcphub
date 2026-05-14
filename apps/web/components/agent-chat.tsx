"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

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
  const logRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [messages]);

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
    const assistantId = `${Date.now()}-a-${Math.random().toString(36).slice(2, 6)}`;
    setMessages((current) => [
      ...current,
      userMessage,
      { id: assistantId, role: "assistant", content: "" }
    ]);
    setInput("");
    setSending(true);

    const historyForRequest = messages.map(({ role, content }) => ({ role, content }));

    try {
      const response = await fetch(`${apiOrigin}/connectors/actionstep/chat/stream`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.token}`,
          accept: "text/event-stream"
        },
        body: JSON.stringify({ message: trimmed, history: historyForRequest })
      });

      if (!response.ok || !response.body) {
        const fallback = await response.text().catch(() => "");
        throw new Error(fallback || `Chat request failed (${response.status})`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let accumulated = "";
      let errored = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let eventEnd = buffer.indexOf("\n\n");
        while (eventEnd !== -1) {
          const rawEvent = buffer.slice(0, eventEnd);
          buffer = buffer.slice(eventEnd + 2);
          eventEnd = buffer.indexOf("\n\n");

          let eventType = "message";
          const dataLines: string[] = [];
          for (const line of rawEvent.split("\n")) {
            if (line.startsWith("event:")) {
              eventType = line.slice(6).trim();
            } else if (line.startsWith("data:")) {
              dataLines.push(line.slice(5).replace(/^ /, ""));
            }
          }
          const dataText = dataLines.join("\n");
          if (!dataText || dataText === "[DONE]") continue;

          let payload: Record<string, unknown> | null = null;
          try {
            payload = JSON.parse(dataText) as Record<string, unknown>;
          } catch {
            continue;
          }

          if (eventType === "error") {
            const msg = typeof payload.message === "string" ? payload.message : "Stream error";
            accumulated = accumulated ? `${accumulated}\n\n${msg}` : msg;
            errored = true;
          } else {
            const type = typeof payload.type === "string" ? payload.type : "";
            if (type === "response.output_text.delta" && typeof payload.delta === "string") {
              accumulated += payload.delta;
            } else if (type === "response.completed" && !accumulated) {
              const response = payload.response as Record<string, unknown> | undefined;
              const outputText = response?.output_text;
              if (typeof outputText === "string") {
                accumulated = outputText;
              }
            } else if (type === "response.failed" || type === "error") {
              const errObj = (payload.error ?? payload) as Record<string, unknown>;
              accumulated = accumulated || (typeof errObj.message === "string" ? errObj.message : "Agent error");
              errored = true;
            }
          }

          setMessages((current) =>
            current.map((message) =>
              message.id === assistantId
                ? {
                    ...message,
                    role: errored ? "system" : "assistant",
                    content: accumulated
                  }
                : message
            )
          );
        }
      }

      if (!accumulated) {
        setMessages((current) =>
          current.map((message) =>
            message.id === assistantId ? { ...message, content: "(no response)" } : message
          )
        );
      }
    } catch (error) {
      setMessages((current) =>
        current.map((message) =>
          message.id === assistantId
            ? {
                ...message,
                role: "system",
                content: error instanceof Error ? error.message : "Could not reach the agent."
              }
            : message
        )
      );
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="chat-shell">
      <div className="chat-log" ref={logRef}>
        {messages.length === 0 ? (
          <div className="chat-empty">
            Ask the Nexian agent about a matter, ticket, contact, workflow, or any tool the platform exposes.
          </div>
        ) : (
          messages.map((message) => (
            <div key={message.id} className={`chat-message ${message.role}`}>
              {message.role === "user" ? (
                message.content
              ) : (
                <div className="chat-markdown">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {message.content || (sending ? "…" : "")}
                  </ReactMarkdown>
                </div>
              )}
            </div>
          ))
        )}
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
