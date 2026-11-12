import { Search, X } from "lucide-react";

interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}// Props

export default function SearchBar({ value, onChange, placeholder = "Search…", className = "" }: Props) {
  return (
    <div className={`relative ${className}`}>
      <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-400 pointer-events-none" />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="input pl-8 pr-8 text-caption"
      />
      {value && (
        <button
          onClick={() => onChange("")}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-400 hover:text-ink-600 dark:hover:text-ink-200"
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
}// SearchBar
