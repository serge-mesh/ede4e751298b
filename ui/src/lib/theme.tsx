import * as React from "react";

export type ThemeChoice = "light" | "dark" | "system";
type Resolved = "light" | "dark";

const KEY = "picket.theme";

function systemTheme(): Resolved {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function readThemeChoice(): ThemeChoice {
  try {
    const v = window.localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    // Storage blocked: follow the system.
  }
  return "system";
}

/** Sets the `dark` class on <html>; called before the first render (no inline script: CSP). */
export function applyTheme(choice: ThemeChoice): Resolved {
  const resolved = choice === "system" ? systemTheme() : choice;
  document.documentElement.classList.toggle("dark", resolved === "dark");
  return resolved;
}

interface ThemeState {
  choice: ThemeChoice;
  resolved: Resolved;
  setChoice: (c: ThemeChoice) => void;
}

const ThemeContext = React.createContext<ThemeState>({
  choice: "system",
  resolved: "light",
  setChoice: () => {},
});

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [choice, setChoiceState] = React.useState<ThemeChoice>(readThemeChoice);
  const [system, setSystem] = React.useState<Resolved>(systemTheme);

  React.useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!mq) return;
    const onChange = () => setSystem(mq.matches ? "dark" : "light");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const resolved: Resolved = choice === "system" ? system : choice;
  React.useEffect(() => {
    document.documentElement.classList.toggle("dark", resolved === "dark");
  }, [resolved]);

  const setChoice = React.useCallback((c: ThemeChoice) => {
    setChoiceState(c);
    try {
      window.localStorage.setItem(KEY, c);
    } catch {
      // Not persisted; the choice still applies to this page.
    }
  }, []);

  const value = React.useMemo(() => ({ choice, resolved, setChoice }), [choice, resolved, setChoice]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return React.useContext(ThemeContext);
}
