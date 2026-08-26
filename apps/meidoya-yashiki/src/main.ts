#!/usr/bin/env node
import { runApp } from "./app.js";

// Nothing but argv lives here. The guard, the guarded writers, the logger and
// the runtime are composed in `app.ts`, where a test can drive them; an entry
// point that owned any of that would be a sink no test could reach.
process.exitCode = await runApp(process.argv.slice(2));
