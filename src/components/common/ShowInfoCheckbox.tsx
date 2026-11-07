import { useUiStore } from "../../stores/uiStore";

// shared "show info findings" setting
export default function ShowInfoCheckbox() {
  const { showInfo, toggleShowInfo } = useUiStore();

  return (
    <label className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 cursor-pointer select-none shrink-0">
      <input
        type="checkbox"
        checked={showInfo}
        onChange={toggleShowInfo}
        className="rounded accent-violet-600"
      />
      Show Info findings
    </label>
  );
}// ShowInfoCheckbox
