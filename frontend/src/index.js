import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@/index.css";
import App from "@/App";

// ===== HARD CACHE BUSTER =====
// If any old service worker was installed, unregister it (leftover from a previous build).
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then((regs) => {
    regs.forEach((r) => r.unregister().catch(() => {}));
  }).catch(() => {});
}
// Clear the CacheStorage from any previous build so stale JS bundles are dropped.
if (typeof caches !== 'undefined' && caches.keys) {
  caches.keys().then((keys) => {
    keys.forEach((k) => caches.delete(k).catch(() => {}));
  }).catch(() => {});
}
// Track version — if it changes between visits, force-refresh once.
const APP_VERSION = '6.0.0-weaponized';
try {
  const cached = localStorage.getItem('__app_version');
  if (cached && cached !== APP_VERSION) {
    localStorage.setItem('__app_version', APP_VERSION);
    // One-shot hard reload with cache bypass
    if (!sessionStorage.getItem('__reload_done')) {
      sessionStorage.setItem('__reload_done', '1');
      window.location.reload();
    }
  } else if (!cached) {
    localStorage.setItem('__app_version', APP_VERSION);
  }
} catch (e) {
  // localStorage may be unavailable (private mode) — safe to ignore for version tracking
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      refetchOnWindowFocus: false,
    },
  },
});

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
);

