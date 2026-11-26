import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The live console talks to tools/bridge.py (default port 8765). In development and in
// `vite preview`, /api is forwarded there so the browser only ever sees one origin.
const bridge = { "/api": { target: "http://127.0.0.1:8765" } };

export default defineConfig({
  plugins: [react()],
  server: { proxy: bridge },
  preview: { proxy: bridge },
});
