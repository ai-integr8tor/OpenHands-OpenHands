/* eslint-disable i18next/no-literal-string */
import React, { useMemo } from "react";
import { useOrgUsageStats } from "#/hooks/query/use-org-usage-stats";
import { useOrgConversations } from "#/hooks/query/use-org-conversations";
import { useSelectedOrganizationId } from "#/context/use-selected-organization";

interface StatCardProps {
  label: string;
  value: string;
  subtitle?: string;
}

function StatCard({ label, value, subtitle }: StatCardProps) {
  return (
    <div className="flex flex-col gap-2 bg-[#111] rounded-lg p-5 border border-[#222]">
      <span className="text-sm text-neutral-400">{label}</span>
      <span className="text-3xl font-semibold text-white">{value}</span>
      {subtitle && (
        <span className="text-xs text-neutral-500">{subtitle}</span>
      )}
    </div>
  );
}

export function UsageDashboard() {
  const { organizationId } = useSelectedOrganizationId();

  const { data: usageStats, isLoading: statsLoading } = useOrgUsageStats({
    days: 7,
  });
  const { data: conversationsData, isLoading: convsLoading } =
    useOrgConversations({ timeWindow: "7d", perPage: 100 });

  const conversationCount = usageStats?.agent_runs ?? 0;
  const totalSpend = usageStats?.estimated_spend ?? 0;
  const avgCost =
    conversationCount > 0 ? totalSpend / conversationCount : 0;

  const modelDistribution = useMemo(() => {
    const items = conversationsData?.items ?? [];
    const counts: Record<string, number> = {};
    for (const conv of items) {
      const model = conv.llm_model || "Unknown";
      counts[model] = (counts[model] ?? 0) + 1;
    }
    const total = items.length;
    return Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .map(([model, count]) => ({
        model,
        count,
        percentage: total > 0 ? Math.round((count / total) * 100) : 0,
      }));
  }, [conversationsData]);

  const isLoading = statsLoading || convsLoading;

  if (!organizationId) {
    return (
      <div className="p-6 text-sm text-neutral-400">
        Select an organization to view usage data.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8 p-2">
      <div>
        <h1 className="text-xl font-semibold text-white mb-1">
          Usage Dashboard
        </h1>
        <p className="text-sm text-neutral-400">Last 7 days</p>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label="Conversations"
          value={isLoading ? "—" : conversationCount.toLocaleString()}
          subtitle="Last 7 days"
        />
        <StatCard
          label="Avg Cost per Conversation"
          value={isLoading ? "—" : `$${avgCost.toFixed(3)}`}
          subtitle={
            totalSpend > 0
              ? `$${totalSpend.toFixed(2)} total spend`
              : undefined
          }
        />
        <StatCard
          label="Models in Use"
          value={isLoading ? "—" : String(modelDistribution.length)}
          subtitle={
            modelDistribution[0]
              ? `Top: ${modelDistribution[0].model}`
              : undefined
          }
        />
      </div>

      {/* Model distribution */}
      <div className="flex flex-col gap-4">
        <h2 className="text-base font-semibold text-white">
          Model Distribution
        </h2>
        {isLoading ? (
          <p className="text-sm text-neutral-400">Loading…</p>
        ) : modelDistribution.length === 0 ? (
          <p className="text-sm text-neutral-400">
            No conversation data for the last 7 days.
          </p>
        ) : (
          <div className="flex flex-col gap-4">
            {modelDistribution.map(({ model, count, percentage }) => (
              <div key={model} className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-mono text-neutral-200 truncate max-w-[55%]">
                    {model}
                  </span>
                  <span className="text-neutral-400 shrink-0 ml-2">
                    {count.toLocaleString()}{" "}
                    {count === 1 ? "conversation" : "conversations"} (
                    {percentage}%)
                  </span>
                </div>
                <div className="h-2 bg-[#222] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-indigo-500 rounded-full transition-all duration-500"
                    style={{ width: `${percentage}%` }}
                  />
                </div>
              </div>
            ))}
            {conversationsData &&
              conversationsData.total_items > 100 && (
                <p className="text-xs text-neutral-500">
                  Distribution based on the first 100 of{" "}
                  {conversationsData.total_items.toLocaleString()} conversations.
                </p>
              )}
          </div>
        )}
      </div>
    </div>
  );
}
