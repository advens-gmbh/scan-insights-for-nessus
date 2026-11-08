type Scale = Record<50 | 100 | 200 | 300 | 400 | 500 | 600 | 700 | 800 | 900 | 950, string>;

interface SeverityColor {
  fill: string;
  on: string;
  fg: { light: string; dark: string };
}

export const ink: Scale;
export const accent: Scale;
export const severity: Record<"critical" | "high" | "medium" | "low" | "info", SeverityColor>;
