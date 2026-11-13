// function that the table pages' rows share

// the row whose panel is open
export const SELECTED_ROW = "!bg-accent-50 dark:!bg-accent-900/30";

const COUNT_COLOR: Record<number, string> = { 4: "text-critical-fg", 3: "text-high-fg", 2: "text-medium-fg", 1: "text-low-fg", 0: "text-info-fg" };

// nothing to show in a cell
export function Dash() {
  return <span className="text-ink-300 dark:text-ink-600">-</span>;
}// Dash

// how many findings of one severity, in its colour, or a dash for none
export function CountCell({ value, severity }: { value: number; severity: number }) {
  return (
    <td className="table-cell text-center">
      {value > 0 ? <span className={`font-semibold text-body ${COUNT_COLOR[severity]}`}>{value.toLocaleString()}</span> : <Dash />}
    </td>
  );
}// CountCell
