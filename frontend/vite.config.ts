import { defineConfig, type ProxyOptions } from "vite";
import react from "@vitejs/plugin-react";

// The live console talks to tools/bridge.py (default port 8765). In development and in
// `vite preview`, /api is forwarded there so the browser only ever sees one origin.
//
// The bridge accepts only its own Host and Origin (DNS-rebinding and cross-site protection), so
// the proxy presents a request from the console page itself as coming from the bridge's origin.
// A request carrying any OTHER origin is forwarded unchanged, and the bridge still refuses it.
const BRIDGE = "http://127.0.0.1:8765";

// The small part of the proxy's event API used here (keeps the config free of Node type packages).
type ProxyEvents = {
  on(
    event: "proxyReq",
    listener: (
      proxyReq: { setHeader(name: string, value: string): void },
      req: { headers: { origin?: string; host?: string } },
    ) => void,
  ): unknown;
};

const bridge: Record<string, ProxyOptions> = {
  "/api": {
    target: BRIDGE,
    changeOrigin: true, // Host header becomes 127.0.0.1:8765
    configure: (proxy) => {
      (proxy as unknown as ProxyEvents).on("proxyReq", (proxyReq, req) => {
        const origin = req.headers.origin;
        if (
          origin &&
          req.headers.host &&
          origin === `http://${req.headers.host}`
        ) {
          proxyReq.setHeader("origin", BRIDGE);
        }
      });
    },
  },
};

export default defineConfig({
  plugins: [react()],
  server: { proxy: bridge },
  preview: { proxy: bridge },
});
