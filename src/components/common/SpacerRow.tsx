export default function SpacerRow({ height, colSpan }: { height: number; colSpan: number }) {
  if (height <= 0) {
    return null;
  }

  return (
    <tr aria-hidden="true" style={{ height }}>
      <td colSpan={colSpan} />
    </tr>
  );
}// SpacerRow
