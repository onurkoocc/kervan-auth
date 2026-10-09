import { ConfigError, loadConfig } from "./config.js";
import { loadSigningKey } from "./keys.js";
import { createLogger, fileSink, stdoutSink, type Sink } from "./log.js";
import { createApp } from "./server.js";

async function main(): Promise<void> {
  const bootLogger = createLogger([stdoutSink()]);
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (!(err instanceof ConfigError)) throw err;
    bootLogger.log("error", "invalid configuration", { reason: err.message });
    process.exit(1);
  }

  const sinks: Sink[] = [stdoutSink()];
  if (config.logFile) sinks.push(fileSink(config.logFile));
  const logger = createLogger(sinks);

  const key = await loadSigningKey(config.signingKeyFile);
  const server = createApp({ config, key, logger });

  server.listen(config.port, () => {
    logger.log("info", "listening", {
      port: config.port,
      issuer: config.issuer,
      kid: key.kid,
      key_source: config.signingKeyFile ? "file" : "generated",
    });
  });

  const shutdown = (signal: string) => {
    logger.log("info", "shutting down", { signal });
    server.close(() => process.exit(0));
    server.closeIdleConnections();
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err: unknown) => {
  process.stdout.write(
    JSON.stringify({
      ts: new Date().toISOString(),
      level: "error",
      service: "auth",
      msg: "failed to start",
      reason: err instanceof Error ? err.message : String(err),
    }) + "\n",
  );
  process.exit(1);
});
