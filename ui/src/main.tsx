import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { applyTheme, readThemeChoice } from "@/lib/theme";
import { makeQueryClient } from "@/lib/query-client";
import { App } from "./app";
import { createAppRouter } from "./router";

// Before the first paint (no inline script in index.html: the CSP forbids it).
applyTheme(readThemeChoice());

const queryClient = makeQueryClient();
const router = createAppRouter(queryClient);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App queryClient={queryClient} router={router} />
  </StrictMode>,
);
