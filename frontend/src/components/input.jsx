// src/components/Input.jsx

export default function Input({ label, type = "text", value, onChange, placeholder }) {
  return (
    <div className="mb-5">
      {label && (
        <label className="block text-[0.7rem] tracking-[0.2em] text-[#7aa3c0] mb-[0.4rem] uppercase font-body">
          {label}
        </label>
      )}
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className="
          w-full px-4 py-[0.8rem]
          bg-[rgba(0,0,0,0.4)] border border-[rgba(0,212,255,0.15)]
          text-slate-100 font-body text-base outline-none
          clip-input transition-all duration-200
          placeholder:text-[rgba(120,163,192,0.4)]
          focus:border-[rgba(0,212,255,0.5)] focus:bg-[rgba(0,212,255,0.04)]
          focus:shadow-[0_0_15px_rgba(0,212,255,0.1)]
        "
      />
    </div>
  );
}
