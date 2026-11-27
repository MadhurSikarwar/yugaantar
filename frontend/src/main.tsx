import { Suspense, lazy, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/instrument-sans/standard.css";
import "./base.css";
import Landing from "./landing/Landing.tsx";

const Console = lazy(() => import("./console/Console.tsx"));

function App() {
  const [route, setRoute] = useState(location.hash);
  useEffect(() => {
    const change = () => {
      setRoute(location.hash);
      if (location.hash.startsWith("#/"))
        window.scrollTo({ top: 0, behavior: "instant" });
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  return route.startsWith("#/console") ? (
    <Suspense fallback={<div className="route-loading">Opening console…</div>}>
      <Console />
    </Suspense>
  ) : (
    <Landing />
  );
}
createRoot(document.getElementById("root")!).render(<App />);
