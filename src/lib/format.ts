export function formatDuration(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 1) return "under a minute";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    const remMin = minutes % 60;
    return remMin === 0
      ? `${hours} hour${hours === 1 ? "" : "s"}`
      : `${hours} h ${remMin} min`;
  }
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours === 0
    ? `${days} day${days === 1 ? "" : "s"}`
    : `${days} day${days === 1 ? "" : "s"}, ${remHours} h`;
}

export function eventTypeLabel(event: {
  category: string;
  attemptType: string | null;
  parseLabel: string;
}): string {
  if (event.category === "attempt") {
    switch (event.attemptType) {
      case "failed_attempt":
        return "failed";
      case "successful_attempt":
        return "success";
      case "invalid_user_probe":
        return "probe";
    }
  }
  if (event.category === "observation") return "observation";
  return "unparsed";
}
