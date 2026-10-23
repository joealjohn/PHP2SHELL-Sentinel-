"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useLogin, useRegister, useSession } from "@/hooks/use-session";
import { Button, Card, Input } from "@/components/ui";

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
    <div className="flex min-h-screen items-center justify-center px-4">
      <Card className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <div className="mb-2 text-2xl font-bold tracking-tight text-white">
            🛡 Sentinel
          </div>
          <p className="text-xs text-slate-500">
            Authorized vulnerability monitoring — detect, verify, explain, disclose.
          </p>
        </div>

        <div className="mb-4 flex rounded-lg border border-[#2a3a55] p-1 text-sm">
          {(["login", "register"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => {
                setMode(m);
                setError(null);
              }}
              className={`flex-1 rounded-md py-1.5 capitalize transition ${
                mode === m ? "bg-[#1f2a3d] text-white" : "text-slate-400"
              }`}
            >
              {m}
            </button>
          ))}
        </div>

        <form onSubmit={submit} className="space-y-3">
          <Input
            type="email"
            required
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
          />
          <Input
            type="password"
            required
            placeholder={mode === "register" ? "12+ chars, upper+lower+digit" : "Password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "register" ? "new-password" : "current-password"}
            minLength={mode === "register" ? 12 : undefined}
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <Button type="submit" disabled={busy} className="w-full justify-center">
            {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
          </Button>
        </form>

        {mode === "register" && (
          <p className="mt-3 text-center text-[11px] text-slate-600">
            Only scan infrastructure you own or are authorized to test.
          </p>
        )}
      </Card>
    </div>
  );
}
