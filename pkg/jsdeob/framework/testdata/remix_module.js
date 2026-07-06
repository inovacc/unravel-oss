// FIXTURE: Remix bundle output. Markers: __remixContext unique, __remixManifest,
// RemixServer component, @remix-run package literal.
window.__remixContext = { state: {} };
window.__remixManifest = { routes: {} };
import { RemixServer } from "@remix-run/react";
function Root() { return RemixServer({}); }
