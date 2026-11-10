import type { CSSProperties } from "react";

export const MIN_COLUMN_WIDTH = 50;

export interface TableColumn<K extends string = string> {
  key: K;
  label: string;
  width: number;           // default width, and the least it gets while filling the table
  stretch?: boolean;       // takes the leftover space until the first drag
  required?: boolean;      // can't be hidden
  defaultHidden?: boolean;
  align?: "left" | "center";
  sortable?: boolean;      // false: the header doesn't sort
  dot?: string;            // colour class of a dot before the label
  info?: boolean;          // is the Info column shown with Show Info and not in the column picker?
}// TableColumn

export interface TableLayout {
  hidden: string[];
  widths: Record<string, number> | null;   // null until a column is dragged
  baseline: Record<string, number> | null; // what the columns measured at the first drag
}// TableLayout

export function defaultLayout(columns: TableColumn[]): TableLayout {
  return { hidden: columns.filter((c) => c.defaultHidden).map((c) => c.key), widths: null, baseline: null };
}// defaultLayout

export function visibleColumns<K extends string>(columns: TableColumn<K>[], layout: TableLayout, showInfo = false): TableColumn<K>[] {
  return columns.filter((c) => (c.info ? showInfo : !layout.hidden.includes(c.key)));
}// visibleColumns

export function toggleColumn(columns: TableColumn[], layout: TableLayout, key: string): TableLayout {
  if (columns.find((c) => c.key === key)?.required) {
    return layout;
  }

  const hidden = layout.hidden.includes(key) ? layout.hidden.filter((k) => k !== key) : [...layout.hidden, key];
  return { ...layout, hidden };
}// toggleColumn

export function columnWidth(column: TableColumn, layout: TableLayout): number | undefined {
  if (layout.widths) {
    return layout.widths[column.key] ?? column.width;
  }

  return column.stretch ? undefined : column.width;
}// columnWidth

export function dragColumn(layout: TableLayout, rendered: Record<string, number>, key: string, width: number): TableLayout {
  return {
    ...layout,
    baseline: layout.baseline ?? rendered,
    widths: { ...rendered, ...layout.widths, [key]: Math.max(MIN_COLUMN_WIDTH, width) },
  };
}// dragColumn

export function tableStyle(visible: TableColumn[], layout: TableLayout): CSSProperties {
  if (layout.widths) {
    const width = visible.reduce((sum, c) => sum + (columnWidth(c, layout) ?? c.width), 0);
    return { tableLayout: "fixed", width };
  }

  return { tableLayout: "fixed", width: "100%", minWidth: visible.reduce((sum, c) => sum + c.width, 0) };
}// tableStyle

export function resetColumnWidth(columns: TableColumn[], layout: TableLayout, key: string): TableLayout {
  if (!layout.widths) {
    return layout;
  }

  const current = layout.widths;
  const original = (k: string) => layout.baseline?.[k] ?? columns.find((c) => c.key === k)?.width ?? current[k];
  const widths = { ...current, [key]: original(key) };

  return Object.keys(widths).some((k) => widths[k] !== original(k))
    ? { ...layout, widths }
    : { ...layout, widths: null, baseline: null };
}// resetColumnWidth
