/// <reference types="vitest/config" />
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run dev` proxies the API (and the UI WebSocket) to a running picket-core.
// PICKET_CORE_DEV_URL defaults to a local test instance (pipelines.md §9).
const coreUrl = process.env.PICKET_CORE_DEV_URL ?? "https://127.0.0.1:8443";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Never inline assets as data: URIs: the CSP (core.md §12) allows data: only for images,
    // and fonts or other assets would fall under default-src 'self'.
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1500,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api/ui/v1/events": {
        target: coreUrl,
        ws: true,
        secure: false,
        changeOrigin: true,
        configure: (proxy) => {
          // Core checks that the WebSocket's Origin is its own (core.md §12).
          proxy.on("proxyReqWs", (req) => req.setHeader("origin", coreUrl));
        },
      },
      "/api": { target: coreUrl, secure: false, changeOrigin: true },
      "/lanca": { target: coreUrl, secure: false, changeOrigin: true },
      "/lists": { target: coreUrl, secure: false, changeOrigin: true },
    },
  },
  test: {
    environment: "jsdom",
    globals: false,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    restoreMocks: true,
    include: ["src/**/*.test.{ts,tsx}"],
    // Whole-app tests wait up to 8 s per step under a loaded machine; CI's shared runner (the Rust
    // job runs beside this one) took over 15 s for the longest flows.
    testTimeout: 45_000,
  },
});
