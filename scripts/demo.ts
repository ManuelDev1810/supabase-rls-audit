// Starts the mock Supabase project from the tests and runs the CLI against it.
// Handy for screenshots and for seeing the output without touching a real project.
import { spawn } from "node:child_process";
import { ANON_KEY, startMockServer } from "../test/mock-server.ts";

const srv = await startMockServer();
const child = spawn(process.execPath, ["src/cli.ts", "--url", srv.url, "--key", ANON_KEY, "--app", srv.url], {
  stdio: "inherit",
  env: { ...process.env, FORCE_COLOR: "1" },
});
child.on("exit", async (code) => {
  await srv.close();
  process.exit(code ?? 0);
});
