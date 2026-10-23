"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useSession } from "@/hooks/use-session";
import { Spinner } from "@/components/ui";

export default function Home() {
  const router = useRouter();
  const { data, isLoading } = useSession();

  useEffect(() => {
    if (isLoading) return;
    router.replace(data ? "/dashboard" : "/login");
  }, [data, isLoading, router]);

  return (
    <div className="flex h-screen items-center justify-center">
      <Spinner />
    </div>
  );
}
