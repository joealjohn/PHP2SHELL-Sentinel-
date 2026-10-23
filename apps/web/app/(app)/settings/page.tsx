"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useLogout } from "@/hooks/use-session";
import { Button, Card, ErrorBanner, Field, Input, SectionTitle } from "@/components/ui";
import { PageHeader } from "@/components/page";

export default function SettingsPage() {
  const router = useRouter();
  const logout = useLogout();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const me = useQuery({ queryKey: ["session"], queryFn: () => api.me() });

  const change = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: async () => {
      setDone(true);
      setError(null);
      await logout.mutateAsync();
      router.replace("/login");
    },
    onError: (e) =>
      setError(e instanceof Error ? e.message : "Password change failed."),
  });

  return (
    <div className="mx-auto max-w-xl p-6">
      <PageHeader title="Settings" subtitle="Your account and workstation credentials." />
      <Card className="mt-6">
        <SectionTitle>Account</SectionTitle>
        {me.data && (
          <div className="text-sm text-slate-300">
            <div>Email: {me.data.email}</div>
            <div className="mt-1 text-xs text-slate-500">
              Member since {new Date(me.data.created_at).toLocaleDateString()} ·
              verified: {me.data.email_verified ? "yes" : "no"}
            </div>
          </div>
        )}
      </Card>

      <Card className="mt-4">
        <SectionTitle>Change password</SectionTitle>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            change.mutate();
          }}
        >
          <Field label="Current password">
            <Input
              type="password"
              required
              placeholder="Current password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
            />
          </Field>
          <Field label="New password" hint="12+ characters, mixed case and digits.">
            <Input
              type="password"
              required
              minLength={12}
              placeholder="New password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
            />
          </Field>
          {error ? <ErrorBanner message={error} /> : null}
          {done && <p className="text-xs text-[var(--status-ok)]">Password changed — please sign in again.</p>}
          <Button type="submit" disabled={change.isPending} className="self-start">
            {change.isPending ? "Saving…" : "Change password"}
          </Button>
        </form>
        <p className="mt-2 text-[11px] text-slate-600">
          Changing your password signs out every session for safety.
        </p>
      </Card>
    </div>
  );
}
