"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, Radar, TriangleAlert } from "lucide-react";
import { ApiError, api } from "@/lib/api";
import { Button, Card, ErrorBanner, Field, Input, Textarea } from "@/components/ui";
import { PageHeader } from "@/components/page";

export default function NewAssetPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [desc, setDesc] = useState("");
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<{ id: string; name: string } | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api.createAsset({
        name,
        url,
        description: desc || undefined,
        monitoring_enabled: true,
        authorization_confirmed: authConfirmed,
      }),
    onSuccess: (a) => {
      setError(null);
      setCreated({ id: a.id, name: a.name });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to create asset."),
  });

  if (created) {
    return (
      <div className="mx-auto max-w-2xl p-6">
        <Card className="animate-fade-in">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 h-6 w-6 text-ok" aria-hidden />
            <div>
              <h1 className="text-lg font-semibold text-ink">
                “{created.name}” is now monitored
              </h1>
              <p className="mt-1 text-sm text-ink-2">
                The asset was registered. Scans run automatically on its schedule —
                or trigger the first scan right now.
              </p>
            </div>
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            <Button
              onClick={() =>
                router.push(`/assets/${created.id}`)
              }
            >
              <Radar className="h-4 w-4" aria-hidden /> Run first scan
            </Button>
            <Button variant="secondary" onClick={() => { setCreated(null); setName(""); setUrl(""); setDesc(""); }}>
              Add another asset
            </Button>
            <Link href="/assets">
              <Button variant="ghost">Back to assets</Button>
            </Link>
          </div>
          <p className="mt-4 text-[11px] text-ink-3">
            Reminder: discovery never attempts any invasive test. Scans only
            fingerprint software versions and read public metadata.
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl p-6">
      <PageHeader
        title="Add asset"
        subtitle="Register a target host for non-invasive monitoring."
      />
      <Card className="mt-6">
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <Field label="Name">
            <Input
              required
              placeholder="Product web server"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          <Field label="URL" hint="Public base URL of the target (https://…).">
            <Input
              required
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </Field>
          <Field label="Description (optional)">
            <Textarea
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              className="min-h-20 font-sans text-sm"
              placeholder="What is this host, who owns it, how is it maintained?"
            />
          </Field>
          <label className="flex items-start gap-2 text-xs text-ink-2">
            <input
              type="checkbox"
              required
              checked={authConfirmed}
              onChange={(e) => setAuthConfirmed(e.target.checked)}
              className="mt-0.5 size-4 shrink-0 rounded border-line-strong bg-[var(--bg-page)] accent-[var(--accent)]"
            />
            <span className="leading-4">
              I confirm I own this host or have written authorization to
              security-test it. Scan scheduling is disabled until this is
              confirmed — required before any scans can run.
            </span>
          </label>
          {error ? <ErrorBanner message={error} /> : null}
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={create.isPending || !authConfirmed}>
              {create.isPending ? "Adding…" : "Add asset"}
            </Button>
            <Button type="button" variant="ghost" onClick={() => router.push("/assets")}>
              Cancel
            </Button>
          </div>
        </form>
      </Card>
      <p className="mt-3 flex items-start gap-2 text-[11px] text-ink-3">
        <TriangleAlert className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
        Only add hosts you own or have written authorization to test. SSRF
        guards block private, loopback, and metadata targets unless
        SCAN_ALLOW_PRIVATE_TARGETS is set for lab testing.
      </p>
    </div>
  );
}
