"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Button, Card, Empty, Spinner } from "@/components/ui";

export default function NotificationsPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api.notifications(),
    refetchInterval: 30_000,
  });

  const read = useMutation({
    mutationFn: (nid: string) => api.markRead(nid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });
  const readAll = useMutation({
    mutationFn: () => api.markAllRead(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });

  return (
    <div className="space-y-6">
      <Card>
        <div className="mb-3 flex items-center justify-between">
          <h1 className="text-lg font-semibold text-white">Notifications</h1>
          {data && data.unread > 0 && (
            <Button variant="secondary" onClick={() => readAll.mutate()} disabled={readAll.isPending}>
              Mark all read
            </Button>
          )}
        </div>
        {isLoading || !data ? (
          <Spinner />
        ) : data.notifications.length === 0 ? (
          <Empty>No notifications.</Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {data.notifications.map((n) => (
              <div key={n.id} className="flex flex-wrap items-start justify-between gap-2 py-3 text-sm">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    {!n.read_at && <Badge color="CRITICAL">new</Badge>}
                    <span className="text-slate-200">{n.title}</span>
                  </div>
                  <div className="mt-0.5 text-xs text-slate-400">{n.message}</div>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-600">
                  {new Date(n.created_at).toLocaleString()}
                  {!n.read_at && (
                    <Button variant="ghost" onClick={() => read.mutate(n.id)}>
                      Mark read
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
