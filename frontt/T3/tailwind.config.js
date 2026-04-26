/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ["'Orbitron'", "monospace"],
        body:    ["'Rajdhani'", "sans-serif"],
      },
      colors: {
        navy:    "#020b18",
        navy2:   "#041020",
        "blue-deep": "#0a1628",
        "blue-mid":  "#0d2240",
        accent:  "#00d4ff",
        accent2: "#0099cc",
        "green-glow": "#00ff9d",
      },
      animation: {
        "sphere-pulse": "spherePulse 6s ease-in-out infinite",
        "ring-rotate":  "ringRotate 20s linear infinite",
        "ring-reverse": "ringRotate 14s linear infinite reverse",
        "ring-fast":    "ringRotate 9s linear infinite",
        "core-pulse":   "corePulse 3s ease-in-out infinite",
        "dot-orbit":    "dotOrbit 12s linear infinite",
        "dot-orbit-2":  "dotOrbit 8s linear infinite",
        "dot-orbit-3":  "dotOrbit 10s linear infinite",
        blink:          "blink 2s ease-in-out infinite",
      },
      keyframes: {
        spherePulse: {
          "0%,100%": { opacity: "0.7", transform: "scale(1)" },
          "50%":     { opacity: "1",   transform: "scale(1.03)" },
        },
        ringRotate: {
          from: { transform: "rotate(0deg) rotateX(60deg)" },
          to:   { transform: "rotate(360deg) rotateX(60deg)" },
        },
        corePulse: {
          "0%,100%": { opacity: "0.6", transform: "scale(1)" },
          "50%":     { opacity: "1",   transform: "scale(1.15)" },
        },
        dotOrbit: {
          from: { transform: "rotate(0deg) translateX(20px)" },
          to:   { transform: "rotate(360deg) translateX(20px)" },
        },
        blink: {
          "0%,100%": { opacity: "1" },
          "50%":     { opacity: "0.3" },
        },
      },
      clipPath: {
        hero:   "polygon(12px 0%, 100% 0%, calc(100% - 12px) 100%, 0% 100%)",
        login:  "polygon(8px 0%,  100% 0%, calc(100% - 8px)  100%, 0% 100%)",
        submit: "polygon(10px 0%, 100% 0%, calc(100% - 10px) 100%, 0% 100%)",
        card:   "polygon(16px 0%, 100% 0%, calc(100% - 16px) 100%, 0% 100%)",
        input:  "polygon(6px 0%,  100% 0%, calc(100% - 6px)  100%, 0% 100%)",
      },
      boxShadow: {
        accent:     "0 0 20px rgba(0,212,255,0.3)",
        "accent-lg":"0 0 40px rgba(0,212,255,0.2)",
        card:       "0 0 60px rgba(0,212,255,0.08), inset 0 1px 0 rgba(0,212,255,0.1)",
      },
      backdropBlur: {
        nav: "12px",
      },
    },
  },
  plugins: [
    // clip-path utility plugin
    function ({ matchUtilities, theme }) {
      matchUtilities(
        { clip: (value) => ({ clipPath: value }) },
        { values: theme("clipPath") }
      );
    },
  ],
};
