export default function Button({ children, onClick, variant = "hero", disabled }) {

  /* ── Login (nav) ── */
  if (variant === "login") {
    return (
      <button
        onClick={onClick}
        className="
          font-display text-[0.7rem] tracking-[0.15em] px-6 py-[0.6rem]
          border border-accent text-accent bg-[rgba(0,212,255,0.05)]
          clip-login cursor-pointer transition-all duration-200
          hover:bg-[rgba(0,212,255,0.15)] hover:shadow-accent hover:-translate-y-px
        "
      >
        {children}
      </button>
    );
  }

  /* ── Submit (auth form) ── */
  if (variant === "submit") {
    return (
      <button
        onClick={onClick}
        disabled={disabled}
        className="
          w-full py-[0.9rem] mt-2
          bg-gradient-to-br from-[rgba(0,212,255,0.15)] to-[rgba(0,80,150,0.25)]
          border border-[rgba(0,212,255,0.4)] text-accent
          font-display text-[0.72rem] tracking-[0.25em] uppercase
          clip-submit cursor-pointer transition-all duration-200
          hover:enabled:bg-gradient-to-br hover:enabled:from-[rgba(0,212,255,0.25)]
          hover:enabled:to-[rgba(0,80,150,0.4)] hover:enabled:shadow-accent
          hover:enabled:-translate-y-px disabled:opacity-50 disabled:cursor-not-allowed
        "
      >
        {children}
      </button>
    );
  }

  /* ── Hero (home menu items) ── */
  return (
    <button
      onClick={onClick}
      className="
        group relative overflow-hidden
        font-body text-[0.95rem] font-medium tracking-[0.12em]
        px-6 py-[0.85rem]
        border border-[rgba(0,212,255,0.2)] bg-[rgba(4,16,32,0.7)] text-slate-200
        clip-hero cursor-pointer transition-all duration-200
        flex items-center justify-between text-left
        hover:border-[rgba(0,212,255,0.5)] hover:bg-[rgba(0,212,255,0.07)]
        hover:text-white hover:translate-x-1
      "
    >
      {/* Left accent bar */}
      <span
        className="
          absolute left-0 top-0 bottom-0 w-[3px]
          bg-accent shadow-[0_0_10px_#00d4ff]
          opacity-0 group-hover:opacity-100 transition-opacity duration-200
        "
      />
      <span>{children}</span>
      <span className="text-accent text-[0.9rem] opacity-60">›</span>
    </button>
  );
}
