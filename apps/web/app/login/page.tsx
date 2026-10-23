"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useLogin, useRegister, useSession } from "@/hooks/use-session";
import { Button, ErrorBanner, Field, Input } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const { data: user, isLoading } = useSession();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const login = useLogin();
  const register = useRegister();

  useEffect(() => {
    if (user && !isLoading) router.replace("/dashboard");
  }, [user, isLoading, router]);

  const busy = login.isPending || register.isPending;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      if (mode === "login") await login.mutateAsync({ email, password });
      else await register.mutateAsync({ email, password });
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--bg-page)] px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <span className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-blue-600 shadow-lg shadow-blue-950/50">
            <ShieldCheck className="h-5 w-5 text-white" aria-hidden />
          </span>
          <h1 className="text-xl font-semibold tracking-[-0.01em] text-slate-100">Sentinel</h1>
          <p className="mt-1.5 text-xs leading-5 text-slate-500">
            Authorized vulnerability monitoring —
            detect, verify, explain, disclose.
            <br />
            Runs entirely on this machine.
          </p>
        </div>

        <div className="card p-6">
          <div className="mb-5 flex rounded-lg border border-[rgba(255,255,255,0.08)] bg-[var(--bg-page)] p-1 text-sm">
            {(["login", "register"] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => {
                  setMode(m);
                  setError(null);
                }}
                className={`flex-1 rounded-md py-1.5 font-medium capitalize transition-colors ${
                  mode === m
                    ? "bg-[#182338] text-slate-100"
                    : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {m === "login" ? "Sign in" : "Create account"}
              </button>
            ))}
          </div>

          <form onSubmit={submit} className="flex flex-col gap-3.5">
            <Field label="Email">
              <Input
                type="email"
                required
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
              />
            </Field>
            <Field
              label="Password"
              hint={mode === "register" ? "12+ characters, upper + lower + digit" : undefined}
            >
              <Input
                type="password"
                required
                placeholder={mode === "register" ? "Choose a strong password" : "Password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={mode === "register" ? "new-password" : "current-password"}
                minLength={mode === "register" ? 12 : undefined}
              />
            </Field>
            {error ? <ErrorBanner message={error} /> : null}
            <Button type="submit" disabled={busy} className="mt-1 w-full justify-center">
              {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
            </Button>
          </form>

          {mode === "register" ? (
            <p className="mt-4 text-center text-[11px] leading-4 text-slate-600">
              Only scan infrastructure you own or are authorized to test —
              every asset requires explicit authorization confirmation before
              scanning runs.
            </p>
          ) : null}
        </div>

        <p className="mt-4 text-center text-[10px] text-slate-700">
          Non-invasive scanning only · local-first · no exploit claims
        </p>
      </div>
    </div>
  );
}
